// Tests d'intégration du relais en clair (phase 1) : chaîne complète
// application -> tlsrelay client -> tlsrelay serveur -> destination d'écho.
// L'intégrité est vérifiée par l'empreinte SHA-256 des flux (PLAN §5.1).

#include "support/net_helpers.hpp"

#include <gtest/gtest.h>
#include <csignal>

using namespace testnet;

namespace {

Config server_config(std::uint16_t destination_port) {
    Config c;
    c.mode = Mode::server;
    c.ports[PortKind::plain].listen = Endpoint{"127.0.0.1", 0};
    c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
    c.whitelist = WhitelistRef{permissive_whitelist()};
    c.destination->dial_timeout = 1s;
    c.destination->dial_backoff = 100ms;
    c.limits.shutdown_timeout = 1s;
    return c;
}

Config client_config(std::uint16_t upstream_port) {
    Config c;
    c.mode = Mode::client;
    c.ports[PortKind::plain] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", upstream_port}, {}};
    c.limits.shutdown_timeout = 1s;
    return c;
}


}  // namespace


TEST(Relay, PlainChainPreservesDataIntegrity) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port()));

    {
        TestClient app(client.port());
        std::string sent;
        const auto received = exchange(app, 1 << 20, 42, &sent);
        ASSERT_EQ(received.size(), sent.size());
        EXPECT_EQ(sha256(received), sha256(sent));
    }

    EXPECT_TRUE(eventually([&] { return client.stats().channels_closed.load() == 1; }));
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    EXPECT_EQ(client.stats().bytes_upstream.load(), 1u << 20);
    EXPECT_EQ(client.stats().bytes_downstream.load(), 1u << 20);
    EXPECT_EQ(client.active_channels(), 0u);
}

TEST(Relay, ManyChannelsInParallel) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port()));

    constexpr int kChannels = 50;
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kChannels; ++i) {
        threads.emplace_back([&, i] {
            try {
                TestClient app(client.port());
                std::string sent;
                const auto received = exchange(app, 256 * 1024, static_cast<std::uint64_t>(i), &sent);
                if (sha256(received) == sha256(sent)) ++ok;
            } catch (const std::exception&) {
            }
        });
    }
    for (auto& t : threads) t.join();

    EXPECT_EQ(ok.load(), kChannels);
    EXPECT_TRUE(eventually([&] { return client.stats().channels_closed.load() == kChannels; }));
    EXPECT_EQ(client.stats().channels_opened.load(), static_cast<std::uint64_t>(kChannels));
}

TEST(Relay, HalfClosePropagatesThroughTheChain) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port()));

    TestClient app(client.port());
    const auto data = make_random_data(64 * 1024, 7);
    app.write(data);
    app.shutdown_send();
    // L'écho renvoie tout puis ferme : la fin de flux doit revenir jusqu'à l'application.
    const auto received = app.read_until_eof(5s);
    EXPECT_EQ(sha256(received), sha256(data));
}

TEST(Relay, IdleTimeoutClosesChannel) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    auto cfg = client_config(server.port());
    cfg.limits.idle_timeout = 300ms;
    RunningService client(std::move(cfg));

    TestClient app(client.port());
    app.write("ping");
    ASSERT_EQ(app.read_exactly(4), "ping");

    const auto start = Clock::now();
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_GE(Clock::now() - start, 250ms);
    EXPECT_TRUE(eventually([&] { return client.stats().channels_idle_closed.load() == 1; }));
    // La fermeture côté client se propage au serveur.
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
}

TEST(Relay, ActivityKeepsChannelOpen) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    auto cfg = client_config(server.port());
    cfg.limits.idle_timeout = 400ms;
    RunningService client(std::move(cfg));

    TestClient app(client.port());
    for (int i = 0; i < 10; ++i) {  // 1 s d'activité, bien au-delà de idle_timeout
        app.write("x");
        ASSERT_EQ(app.read_exactly(1, 1s), "x") << "itération " << i;
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_EQ(client.stats().channels_idle_closed.load(), 0u);
}

TEST(Relay, DestinationUnreachableAfterThreeAttempts) {
    ReservedPort unreachable;
    auto cfg = server_config(unreachable.port());
    cfg.destination->dial_retries = 3;
    cfg.destination->dial_backoff = 100ms;  // attentes : 100 ms puis 200 ms
    RunningService server(std::move(cfg));

    TestClient app(server.port());
    const auto start = Clock::now();
    EXPECT_TRUE(app.wait_closed(5s));
    EXPECT_GE(Clock::now() - start, 250ms);
    EXPECT_TRUE(eventually([&] { return server.stats().dial_failures.load() == 1; }));
    EXPECT_EQ(server.stats().dial_attempt_failures.load(), 3u);
}

TEST(Relay, DestinationRetrySucceeds) {
    ReservedPort reserved;
    auto cfg = server_config(reserved.port());
    cfg.destination->dial_retries = 3;
    cfg.destination->dial_backoff = 200ms;
    // Délai court : sous Windows, une connexion vers un port fermé n'est pas
    // refusée immédiatement mais reste en attente jusqu'au délai.
    cfg.destination->dial_timeout = 100ms;
    RunningService server(std::move(cfg));

    // Essais : t=0 (échec avant 100 ms), ~200-300 ms (échec avant ~400 ms), puis ≥ 600 ms.
    TestClient app(server.port());
    app.write("hello");  // mis en tampon pendant les essais
    std::this_thread::sleep_for(500ms);
    EchoServer echo(reserved);  // la destination devient disponible avant le 3e essai

    EXPECT_EQ(app.read_exactly(5, 3s), "hello");
    EXPECT_EQ(server.stats().dial_attempt_failures.load(), 2u);
    EXPECT_EQ(server.stats().dial_failures.load(), 0u);
}

TEST(Relay, MaxChannelsRejectsExtraConnections) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.max_channels = 2;
    RunningService server(std::move(cfg));

    TestClient first(server.port());
    TestClient second(server.port());
    first.write("a");
    second.write("b");
    ASSERT_EQ(first.read_exactly(1), "a");
    ASSERT_EQ(second.read_exactly(1), "b");

    TestClient third(server.port());
    EXPECT_TRUE(third.wait_closed(2s));
    EXPECT_EQ(server.stats().channels_rejected.load(), 1u);

    first.write("c");
    EXPECT_EQ(first.read_exactly(1), "c");  // les canaux existants ne sont pas affectés
}

TEST(Relay, GracefulStopDrainsThenClosesRemainingChannels) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.shutdown_timeout = 300ms;
    RunningService server(std::move(cfg));
    const auto port = server.port();

    TestClient app(port);
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    const auto start = Clock::now();
    server.stop();  // le canal reste ouvert : fermeture forcée à l'échéance du drain
    const auto elapsed = Clock::now() - start;
    EXPECT_GE(elapsed, 250ms);
    EXPECT_LT(elapsed, 3s);
    EXPECT_TRUE(app.wait_closed(1s));
    EXPECT_THROW(TestClient{port}, std::system_error);  // plus aucune connexion acceptée
}

TEST(Relay, GracefulStopWithoutChannelsIsImmediate) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    const auto start = Clock::now();
    server.stop();
    EXPECT_LT(Clock::now() - start, 500ms);
}

TEST(Relay, AbortClosesChannelsImmediately) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.shutdown_timeout = 30s;
    RunningService server(std::move(cfg));

    TestClient app(server.port());
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    const auto start = Clock::now();
    server.abort();
    EXPECT_LT(Clock::now() - start, 1s);
    EXPECT_TRUE(app.wait_closed(1s));
}

TEST(Relay, SignalTriggersGracefulStop) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), relay::ServiceOptions{true, 2});
    std::this_thread::sleep_for(50ms);  // run() a démarré
    std::raise(SIGINT);
    EXPECT_TRUE(server.wait_finished(3s));
}

TEST(Relay, SecondSignalForcesImmediateStop) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.shutdown_timeout = 30s;
    RunningService server(std::move(cfg), relay::ServiceOptions{true, 2});

    TestClient app(server.port());
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    std::raise(SIGINT);  // drain de 30 s : le canal reste ouvert
    std::this_thread::sleep_for(200ms);
    std::raise(SIGINT);  // arrêt immédiat
    EXPECT_TRUE(server.wait_finished(2s));
    EXPECT_TRUE(app.wait_closed(1s));
}
