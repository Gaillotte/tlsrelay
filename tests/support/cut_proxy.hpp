#pragma once

// Test TCP relay placed between two tlsrelay instances: cut() abruptly cuts
// (RST) all current connections, freeze() makes them silent without
// closing them (dead link without a TCP error), to simulate a network failure.

#include "support/net_helpers.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/write.hpp>

#include <array>
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace testnet {

class CutProxy {
public:
    explicit CutProxy(std::uint16_t target) : acceptor_(io_), target_(target) {
        acceptor_.open(tcp::v4());
        acceptor_.bind(tcp::endpoint(loopback(), 0));
        acceptor_.listen();
        asio::co_spawn(io_, accept(), asio::detached);
        thread_ = std::thread([this] { io_.run(); });
    }

    ~CutProxy() {
        asio::post(io_, [this] {
            std::error_code ignored;
            acceptor_.close(ignored);
            close_all();
        });
        thread_.join();
    }

    CutProxy(const CutProxy&) = delete;
    CutProxy& operator=(const CutProxy&) = delete;

    std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

    // Connections accepted since startup.
    int connections() const { return accepted_.load(); }

    // Current connections no longer transmit anything (data dropped), without
    // being closed; the following ones are relayed normally.
    void freeze() {
        std::promise<void> done;
        asio::post(io_, [&] {
            *frozen_ = true;
            frozen_ = std::make_shared<bool>(false);
            done.set_value();
        });
        done.get_future().wait();
    }

    // Cuts all current connections; the following ones are relayed normally.
    void cut() {
        std::promise<void> done;
        asio::post(io_, [&] {
            close_all();
            done.set_value();
        });
        done.get_future().wait();
    }

    // The next n connections are cut (RST) on receipt of their
    // first bytes (ClientHello): failure during the handshake.
    void reset_next(int n) { reset_next_ = n; }

private:
    using Socket = std::shared_ptr<tcp::socket>;

    asio::awaitable<void> accept() {
        for (;;) {
            auto [ec, socket] = co_await acceptor_.async_accept(use_tuple);
            if (ec) co_return;
            ++accepted_;
            if (reset_next_ > 0) {
                --reset_next_;
                std::array<char, 512> hello;
                co_await socket.async_read_some(asio::buffer(hello), use_tuple);
                std::error_code ignored;
                socket.set_option(asio::socket_base::linger(true, 0), ignored);
                socket.close(ignored);
                continue;
            }
            auto in = std::make_shared<tcp::socket>(std::move(socket));
            auto out = std::make_shared<tcp::socket>(io_);
            auto [cec] = co_await out->async_connect(tcp::endpoint(loopback(), target_), use_tuple);
            if (cec) continue;
            std::error_code ignored;
            in->set_option(tcp::no_delay(true), ignored);
            out->set_option(tcp::no_delay(true), ignored);
            sockets_.push_back(in);
            sockets_.push_back(out);
            asio::co_spawn(io_, pump(in, out, frozen_), asio::detached);
            asio::co_spawn(io_, pump(out, in, frozen_), asio::detached);
        }
    }

    static asio::awaitable<void> pump(Socket from, Socket to, std::shared_ptr<bool> frozen) {
        std::array<char, 16 * 1024> buffer;
        std::error_code ignored;
        for (;;) {
            auto [ec, n] = co_await from->async_read_some(asio::buffer(buffer), use_tuple);
            if (ec) {
                if (ec == asio::error::eof) to->shutdown(tcp::socket::shutdown_send, ignored);
                else to->close(ignored);
                co_return;
            }
            if (*frozen) continue;  // silent link: the data is lost
            auto [wec, written] = co_await asio::async_write(*to, asio::buffer(buffer.data(), n), use_tuple);
            (void)written;
            if (wec) {
                from->close(ignored);
                co_return;
            }
        }
    }

    void close_all() {
        std::error_code ignored;
        for (auto& s : sockets_) {
            s->set_option(asio::socket_base::linger(true, 0), ignored);  // RST
            s->close(ignored);
        }
        sockets_.clear();
    }

    asio::io_context io_;
    tcp::acceptor acceptor_;
    std::uint16_t target_;
    std::vector<Socket> sockets_;  // accessed only on the io_ thread
    std::shared_ptr<bool> frozen_ = std::make_shared<bool>(false);  // current connections (io_ thread)
    std::atomic<int> accepted_{0};
    std::atomic<int> reset_next_{0};
    std::thread thread_;
};

}  // namespace testnet
