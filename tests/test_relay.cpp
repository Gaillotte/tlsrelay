// Integration tests of the plain relay (phase 1): full chain
// application -> tlsrelay client -> tlsrelay server -> echo destination.
// Integrity is checked with the SHA-256 digest of the streams (PLAN §5.1).

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
    // The echo sends everything back then closes: the end of stream must come back to the application.
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
    // The close on the client side propagates to the server.
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
}

TEST(Relay, ActivityKeepsChannelOpen) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    auto cfg = client_config(server.port());
    cfg.limits.idle_timeout = 400ms;
    RunningService client(std::move(cfg));

    TestClient app(client.port());
    for (int i = 0; i < 10; ++i) {  // 1 s of activity, well beyond idle_timeout
        app.write("x");
        ASSERT_EQ(app.read_exactly(1, 1s), "x") << "iteration " << i;
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_EQ(client.stats().channels_idle_closed.load(), 0u);
}

TEST(Relay, DestinationUnreachableAfterThreeAttempts) {
    ReservedPort unreachable;
    auto cfg = server_config(unreachable.port());
    cfg.destination->dial_retries = 3;
    cfg.destination->dial_backoff = 100ms;  // waits: 100 ms then 200 ms
    RunningService server(std::move(cfg));
    RunningService client(client_config(server.port()));  // the server only speaks the tunnel protocol

    TestClient app(client.port());
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
    // Short timeout: on Windows, a connection to a closed port is not
    // refused immediately but stays pending until the timeout.
    cfg.destination->dial_timeout = 100ms;
    RunningService server(std::move(cfg));
    RunningService client(client_config(server.port()));  // the server only speaks the tunnel protocol

    // Attempts: t=0 (failure before 100 ms), ~200-300 ms (failure before ~400 ms), then ≥ 600 ms.
    TestClient app(client.port());
    app.write("hello");  // buffered during the attempts
    std::this_thread::sleep_for(500ms);
    EchoServer echo(reserved);  // the destination becomes available before the 3rd attempt

    EXPECT_EQ(app.read_exactly(5, 3s), "hello");
    EXPECT_EQ(server.stats().dial_attempt_failures.load(), 2u);
    EXPECT_EQ(server.stats().dial_failures.load(), 0u);
}

TEST(Relay, MaxChannelsRejectsExtraConnections) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.max_channels = 2;
    RunningService server(std::move(cfg));
    RunningService client(client_config(server.port()));  // the server only speaks the tunnel protocol

    TestClient first(client.port());
    TestClient second(client.port());
    first.write("a");
    second.write("b");
    ASSERT_EQ(first.read_exactly(1), "a");
    ASSERT_EQ(second.read_exactly(1), "b");

    TestClient third(client.port());
    EXPECT_TRUE(third.wait_closed(2s));
    EXPECT_EQ(server.stats().channels_rejected.load(), 1u);

    first.write("c");
    EXPECT_EQ(first.read_exactly(1), "c");  // existing channels are not affected
}

TEST(Relay, GracefulStopDrainsThenClosesRemainingChannels) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.shutdown_timeout = 300ms;
    RunningService server(std::move(cfg));
    RunningService client(client_config(server.port()));  // the server only speaks the tunnel protocol
    const auto port = server.port();

    TestClient app(client.port());
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    const auto start = Clock::now();
    server.stop();  // the channel stays open: forced close when the drain expires
    const auto elapsed = Clock::now() - start;
    EXPECT_GE(elapsed, 250ms);
    EXPECT_LT(elapsed, 3s);
    EXPECT_TRUE(app.wait_closed(1s));
    EXPECT_THROW(TestClient{port}, std::system_error);  // no more connections accepted
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
    RunningService client(client_config(server.port()));  // the server only speaks the tunnel protocol

    TestClient app(client.port());
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
    std::this_thread::sleep_for(50ms);  // run() has started
    std::raise(SIGINT);
    EXPECT_TRUE(server.wait_finished(3s));
}

TEST(Relay, SecondSignalForcesImmediateStop) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.shutdown_timeout = 30s;
    RunningService server(std::move(cfg), relay::ServiceOptions{true, 2});
    RunningService client(client_config(server.port()));  // the server only speaks the tunnel protocol

    TestClient app(client.port());
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    std::raise(SIGINT);  // 30 s drain: the channel stays open
    std::this_thread::sleep_for(200ms);
    std::raise(SIGINT);  // immediate shutdown
    EXPECT_TRUE(server.wait_finished(2s));
    EXPECT_TRUE(app.wait_closed(1s));
}
