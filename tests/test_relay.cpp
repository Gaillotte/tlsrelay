// Tests d'intégration du relais en clair (phase 1) : chaîne complète
// application -> tlsrelay client -> tlsrelay serveur -> destination d'écho.
// L'intégrité est vérifiée par l'empreinte SHA-256 des flux (PLAN §5.1).

#include "tlsrelay/relay/service.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace tlsrelay;
using namespace std::chrono_literals;
using asio::ip::tcp;
using Clock = std::chrono::steady_clock;

namespace {

constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

const asio::ip::address& loopback() {
    static const auto addr = asio::ip::make_address("127.0.0.1");
    return addr;
}

// Destination d'écho : renvoie tout ce qu'elle reçoit et ferme son sens
// d'émission quand le flux entrant se termine.
class EchoServer {
public:
    explicit EchoServer(std::uint16_t port = 0) : acceptor_(io_) {
        const tcp::endpoint ep(loopback(), port);
        acceptor_.open(ep.protocol());
#ifndef _WIN32
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
#endif
        acceptor_.bind(ep);
        acceptor_.listen();
        asio::co_spawn(io_, accept(), asio::detached);
        thread_ = std::thread([this] { io_.run(); });
    }

    ~EchoServer() {
        io_.stop();
        thread_.join();
    }

    std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

private:
    asio::awaitable<void> accept() {
        for (;;) {
            auto [ec, socket] = co_await acceptor_.async_accept(use_tuple);
            if (ec) co_return;
            asio::co_spawn(io_, echo(std::move(socket)), asio::detached);
        }
    }

    static asio::awaitable<void> echo(tcp::socket socket) {
        socket.set_option(tcp::no_delay(true));
        std::array<char, 8192> buffer;
        for (;;) {
            auto [ec, n] = co_await socket.async_read_some(asio::buffer(buffer), use_tuple);
            if (ec) {
                std::error_code ignored;
                if (ec == asio::error::eof) socket.shutdown(tcp::socket::shutdown_send, ignored);
                co_return;
            }
            auto [wec, written] = co_await asio::async_write(socket, asio::buffer(buffer.data(), n), use_tuple);
            (void)written;
            if (wec) co_return;
        }
    }

    asio::io_context io_;
    tcp::acceptor acceptor_;
    std::thread thread_;
};

// Port TCP libre (rien n'y écoute au retour de la fonction).
std::uint16_t free_port() {
    asio::io_context io;
    tcp::acceptor probe(io, tcp::endpoint(loopback(), 0));
    return probe.local_endpoint().port();
}

// Client de test bloquant, avec délais : simule l'application.
class TestClient {
public:
    explicit TestClient(std::uint16_t port) : socket_(io_) {
        socket_.connect(tcp::endpoint(loopback(), port));
        socket_.set_option(tcp::no_delay(true));
    }

    void write(const std::string& data) { asio::write(socket_, asio::buffer(data)); }

    void shutdown_send() { socket_.shutdown(tcp::socket::shutdown_send); }

    // Lit exactement n octets ; retourne moins si le flux se termine ou si le délai expire.
    std::string read_exactly(std::size_t n, std::chrono::milliseconds timeout = 5s) {
        std::string out;
        const auto deadline = Clock::now() + timeout;
        while (out.size() < n) {
            auto [ec, chunk] = read_some(std::min<std::size_t>(n - out.size(), 65536), deadline);
            if (ec) break;
            out += chunk;
        }
        return out;
    }

    std::string read_until_eof(std::chrono::milliseconds timeout = 5s) {
        std::string out;
        const auto deadline = Clock::now() + timeout;
        for (;;) {
            auto [ec, chunk] = read_some(65536, deadline);
            out += chunk;
            if (ec) {
                last_error_ = ec;
                return out;
            }
        }
    }

    // Vrai si la connexion est fermée par l'autre bout dans le délai.
    bool wait_closed(std::chrono::milliseconds timeout) {
        read_until_eof(timeout);
        return last_error_ && last_error_ != asio::error::timed_out;
    }

private:
    std::pair<std::error_code, std::string> read_some(std::size_t max, Clock::time_point deadline) {
        std::string buffer(max, '\0');
        std::error_code result = asio::error::timed_out;
        std::size_t received = 0;
        bool done = false;
        socket_.async_read_some(asio::buffer(buffer), [&](std::error_code ec, std::size_t n) {
            result = ec;
            received = n;
            done = true;
        });
        io_.restart();
        const auto now = Clock::now();
        io_.run_for(deadline > now ? deadline - now : Clock::duration::zero());
        if (!done) {
            socket_.cancel();
            io_.restart();
            io_.run();
            result = asio::error::timed_out;
            received = 0;
        }
        buffer.resize(received);
        return {result, buffer};
    }

    asio::io_context io_;
    tcp::socket socket_;
    std::error_code last_error_;
};

// Service exécuté dans un thread, arrêté proprement à la destruction.
class RunningService {
public:
    explicit RunningService(Config config, relay::ServiceOptions options = {false, 2})
        : service_(std::make_unique<relay::Service>(std::move(config), options)),
          thread_([this] {
              service_->run();
              finished_ = true;
          }) {}

    // Attend la fin de run() (arrêt déclenché autrement, par exemple par un signal).
    bool wait_finished(std::chrono::milliseconds timeout) {
        if (!eventually_finished(timeout)) return false;
        thread_.join();
        return true;
    }

    ~RunningService() { stop(); }

    void stop() {
        if (!thread_.joinable()) return;
        service_->request_stop();
        thread_.join();
    }

    void abort() {
        if (!thread_.joinable()) return;
        service_->request_abort();
        thread_.join();
    }

    std::uint16_t port() const { return service_->local_endpoint(PortKind::plain)->port(); }
    const relay::Stats& stats() const { return service_->stats(); }
    std::size_t active_channels() const { return service_->active_channels(); }

private:
    bool eventually_finished(std::chrono::milliseconds timeout) {
        const auto deadline = Clock::now() + timeout;
        while (Clock::now() < deadline) {
            if (finished_) return true;
            std::this_thread::sleep_for(10ms);
        }
        return finished_.load();
    }

    std::atomic<bool> finished_{false};
    std::unique_ptr<relay::Service> service_;
    std::thread thread_;
};

Config server_config(std::uint16_t destination_port) {
    Config c;
    c.mode = Mode::server;
    c.ports[PortKind::plain].listen = Endpoint{"127.0.0.1", 0};
    c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
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

std::string make_random_data(std::size_t size, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::string data(size, '\0');
    for (auto& c : data) c = static_cast<char>(rng() & 0xff);
    return data;
}

std::string sha256(const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), nullptr);
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned i = 0; i < length; ++i) {
        out += hex[digest[i] >> 4];
        out += hex[digest[i] & 0xf];
    }
    return out;
}

// Envoie size octets par blocs et relit l'écho de chaque bloc ; retourne les octets reçus.
std::string exchange(TestClient& client, std::size_t size, std::uint64_t seed, std::string* sent = nullptr) {
    const auto data = make_random_data(size, seed);
    std::string received;
    constexpr std::size_t kChunk = 16 * 1024;
    for (std::size_t offset = 0; offset < data.size(); offset += kChunk) {
        const auto chunk = data.substr(offset, kChunk);
        client.write(chunk);
        received += client.read_exactly(chunk.size());
    }
    if (sent) *sent = data;
    return received;
}

template <class Predicate>
bool eventually(Predicate predicate, std::chrono::milliseconds timeout = 3s) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return predicate();
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
    auto cfg = server_config(free_port());
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
    const auto port = free_port();
    auto cfg = server_config(port);
    cfg.destination->dial_retries = 3;
    cfg.destination->dial_backoff = 200ms;  // essais à t=0, 200 ms, 600 ms
    RunningService server(std::move(cfg));

    TestClient app(server.port());
    app.write("hello");  // mis en tampon pendant les essais
    std::this_thread::sleep_for(350ms);
    EchoServer echo(port);  // la destination devient disponible avant le 3e essai

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

TEST(Relay, TlsPortsAreNotYetAvailable) {
    auto cfg = server_config(9);
    cfg.ports[PortKind::tls].listen = Endpoint{"127.0.0.1", 0};
    EXPECT_THROW(relay::Service service(cfg), std::runtime_error);
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
