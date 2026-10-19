#pragma once

// Network tools shared by the integration tests: echo destination,
// test client with timeouts, service run in a thread, digests.

#include "tlsrelay/relay/service.hpp"

#include "support/test_pki.hpp"

#include <filesystem>
#include <fstream>
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

namespace testnet {

using namespace tlsrelay;
using namespace std::chrono_literals;
using asio::ip::tcp;
using Clock = std::chrono::steady_clock;


inline constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

// Test whitelist, valid for the whole process: 127.0.0.0/8 on the
// plain and tls ports.
inline std::string permissive_whitelist() {
    static const testpki::TempDir dir;
    static const std::string path = [] {
        const auto file = dir / "whitelist.yaml";
        std::ofstream(file) << "peers:\n  - name: local\n    ip: 127.0.0.0/8\n    ports: [plain, tls]\n";
        return file.string();
    }();
    return path;
}

inline const asio::ip::address& loopback() {
    static const auto addr = asio::ip::make_address("127.0.0.1");
    return addr;
}

// Reserved port: bound but not listening. Connections to it are refused, and
// no other process (tests run in parallel) can obtain it.
class ReservedPort {
public:
    ReservedPort() : acceptor_(io_) {
        acceptor_.open(tcp::v4());
        acceptor_.bind(tcp::endpoint(loopback(), 0));
    }
    std::uint16_t port() const { return acceptor_.local_endpoint().port(); }
    // Hands the port (already bound) over to a server that will listen on it.
    tcp::acceptor::native_handle_type release() { return acceptor_.release(); }

private:
    asio::io_context io_;
    tcp::acceptor acceptor_;
};

// Echo destination: sends back everything it receives and closes its send
// direction when the incoming stream ends.
class EchoServer {
public:
    // socket_buffer: reduced kernel buffers (bytes) of the accepted connections,
    // for a destination that blocks quickly (it only reads if it can write).
    explicit EchoServer(int socket_buffer = 0) : acceptor_(io_) {
        acceptor_.open(tcp::v4());
        if (socket_buffer > 0) {
            acceptor_.set_option(asio::socket_base::receive_buffer_size(socket_buffer));
            acceptor_.set_option(asio::socket_base::send_buffer_size(socket_buffer));
        }
        acceptor_.bind(tcp::endpoint(loopback(), 0));
        start();
    }

    // Listens on a port reserved until then (destination that becomes available).
    explicit EchoServer(ReservedPort& reserved) : acceptor_(io_) {
        acceptor_.assign(tcp::v4(), reserved.release());
        start();
    }

    ~EchoServer() {
        io_.stop();
        thread_.join();
    }

    std::uint16_t port() const { return acceptor_.local_endpoint().port(); }
    int accepted() const { return accepted_.load(); }

private:
    void start() {
        acceptor_.listen();
        asio::co_spawn(io_, accept(), asio::detached);
        thread_ = std::thread([this] { io_.run(); });
    }

    asio::awaitable<void> accept() {
        for (;;) {
            auto [ec, socket] = co_await acceptor_.async_accept(use_tuple);
            if (ec) co_return;
            ++accepted_;
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
    std::atomic<int> accepted_{0};
    std::thread thread_;
};


// Blocking test client, with timeouts: simulates the application.
class TestClient {
public:
    explicit TestClient(std::uint16_t port) : socket_(io_) {
        socket_.connect(tcp::endpoint(loopback(), port));
        socket_.set_option(tcp::no_delay(true));
    }

    void write(const std::string& data) { asio::write(socket_, asio::buffer(data)); }

    void shutdown_send() { socket_.shutdown(tcp::socket::shutdown_send); }

    // Reads exactly n bytes; returns fewer if the stream ends or if the timeout expires.
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

    // True if the connection is closed by the other end within the timeout.
    bool wait_closed(std::chrono::milliseconds timeout) {
        read_until_eof(timeout);
        return last_error_ && last_error_ != asio::error::timed_out;
    }

    // Reads what arrives before the deadline (at most max bytes); error is
    // asio::error::timed_out if nothing arrived.
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
            // The read may have completed just before the cancellation: its data is kept.
            if (result == asio::error::operation_aborted) {
                result = asio::error::timed_out;
                received = 0;
            }
        }
        buffer.resize(received);
        return {result, buffer};
    }

private:

    asio::io_context io_;
    tcp::socket socket_;
    std::error_code last_error_;
};

// Service run in a thread, stopped gracefully on destruction.
// Configuration without an administration channel at the default location:
// shared between tests run in parallel, it would act as a common lock.
inline Config without_default_admin(Config config) {
    if (!config.admin.endpoint) config.admin.enabled = false;
    return config;
}

class RunningService {
public:
    // Administration channel disabled, unless the test gives admin.endpoint:
    // the default location would be shared between the tests.
    explicit RunningService(Config config, relay::ServiceOptions options = {false, 2})
        : service_(std::make_unique<relay::Service>(without_default_admin(std::move(config)), options)),
          thread_([this] {
              service_->run();
              finished_ = true;
          }) {}

    // Waits for run() to finish (shutdown triggered otherwise, for example by a signal).
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

    std::uint16_t port(PortKind kind = PortKind::plain) const { return service_->local_endpoint(kind)->port(); }
    relay::Service& service() { return *service_; }
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

inline std::string make_random_data(std::size_t size, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::string data(size, '\0');
    for (auto& c : data) c = static_cast<char>(rng() & 0xff);
    return data;
}

inline std::string sha256(const std::string& data) {
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

// Sends size bytes in blocks and reads back the echo of each block; returns the bytes received.
inline std::string exchange(TestClient& client, std::size_t size, std::uint64_t seed, std::string* sent = nullptr) {
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


}  // namespace testnet
