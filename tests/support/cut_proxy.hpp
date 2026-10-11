#pragma once

// Relais TCP de test placé entre deux tlsrelay : cut() coupe brutalement
// (RST) toutes les connexions en cours, pour simuler une panne réseau.

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

    // Connexions acceptées depuis le démarrage.
    int connections() const { return accepted_.load(); }

    // Coupe toutes les connexions en cours ; les suivantes sont relayées normalement.
    void cut() {
        std::promise<void> done;
        asio::post(io_, [&] {
            close_all();
            done.set_value();
        });
        done.get_future().wait();
    }

private:
    using Socket = std::shared_ptr<tcp::socket>;

    asio::awaitable<void> accept() {
        for (;;) {
            auto [ec, socket] = co_await acceptor_.async_accept(use_tuple);
            if (ec) co_return;
            ++accepted_;
            auto in = std::make_shared<tcp::socket>(std::move(socket));
            auto out = std::make_shared<tcp::socket>(io_);
            auto [cec] = co_await out->async_connect(tcp::endpoint(loopback(), target_), use_tuple);
            if (cec) continue;
            std::error_code ignored;
            in->set_option(tcp::no_delay(true), ignored);
            out->set_option(tcp::no_delay(true), ignored);
            sockets_.push_back(in);
            sockets_.push_back(out);
            asio::co_spawn(io_, pump(in, out), asio::detached);
            asio::co_spawn(io_, pump(out, in), asio::detached);
        }
    }

    static asio::awaitable<void> pump(Socket from, Socket to) {
        std::array<char, 16 * 1024> buffer;
        std::error_code ignored;
        for (;;) {
            auto [ec, n] = co_await from->async_read_some(asio::buffer(buffer), use_tuple);
            if (ec) {
                if (ec == asio::error::eof) to->shutdown(tcp::socket::shutdown_send, ignored);
                else to->close(ignored);
                co_return;
            }
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
    std::vector<Socket> sockets_;  // accédé uniquement sur le thread de io_
    std::atomic<int> accepted_{0};
    std::thread thread_;
};

}  // namespace testnet
