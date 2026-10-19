// Network disturbances between two tlsrelay instances (PLAN §5, in the manner of
// toxiproxy): added latency, limited throughput, periodic cuts (RST),
// periodic silent link.

#include "proxy.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/write.hpp>

#include <iostream>
#include <list>
#include <mutex>

namespace testkit {
namespace {

struct Link {
    tcp::socket in;
    tcp::socket out;
    bool frozen = false;
};

class Proxy {
public:
    Proxy(asio::io_context& io, const tcp::endpoint& listen, const tcp::endpoint& target, const ProxyOptions& options)
        : io_(io), acceptor_(io), target_(target), options_(options), cut_timer_(io) {
        acceptor_.open(listen.protocol());
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
        acceptor_.bind(listen);
        acceptor_.listen(asio::socket_base::max_listen_connections);
        std::cout << "proxy " << acceptor_.local_endpoint() << " -> " << target_ << '\n' << std::flush;
    }

    void start() {
        asio::co_spawn(io_, accept(), asio::detached);
        if (options_.cut_every > Clock::duration::zero()) asio::co_spawn(io_, cutter(), asio::detached);
    }

    void stop() {
        std::error_code ignored;
        acceptor_.close(ignored);
        cut_timer_.cancel();
        cut_all(false);
    }

private:
    asio::awaitable<void> accept() {
        for (;;) {
            auto strand = asio::make_strand(io_);
            auto [ec, in] = co_await acceptor_.async_accept(strand, use_tuple);
            if (ec) {
                if (!acceptor_.is_open()) co_return;
                continue;
            }
            auto link = std::make_shared<Link>(Link{std::move(in), tcp::socket(strand)});
            if (options_.source) {
                // The downstream relay sees the real client's address (whitelist by IP).
                std::error_code bec;
                link->out.open(target_.protocol(), bec);
                if (!bec) link->out.bind(tcp::endpoint(*options_.source, 0), bec);
                if (bec) {
                    std::cerr << "source address " << *options_.source << ": " << bec.message() << '\n';
                    continue;
                }
            }
            auto [cec] = co_await link->out.async_connect(target_, use_tuple);
            if (cec) continue;
            std::error_code ignored;
            link->in.set_option(tcp::no_delay(true), ignored);
            link->out.set_option(tcp::no_delay(true), ignored);
            {
                std::lock_guard lock(mutex_);
                links_.push_back(link);
            }
            asio::co_spawn(strand, pump(link, true), asio::detached);
            asio::co_spawn(strand, pump(link, false), asio::detached);
        }
    }

    asio::awaitable<void> pump(std::shared_ptr<Link> link, bool upstream) {
        auto& from = upstream ? link->in : link->out;
        auto& to = upstream ? link->out : link->in;
        std::vector<unsigned char> buffer(16ULL * 1024);
        asio::steady_timer timer(co_await asio::this_coro::executor);
        for (;;) {
            auto [ec, n] = co_await from.async_read_some(asio::buffer(buffer), use_tuple);
            std::error_code ignored;
            if (ec) {
                if (ec == asio::error::eof) to.shutdown(tcp::socket::shutdown_send, ignored);
                else to.close(ignored);
                co_return;
            }
            if (link->frozen) continue;  // silent link: data lost, without error
            if (options_.delay > Clock::duration::zero()) {
                timer.expires_after(options_.delay);
                co_await timer.async_wait(use_tuple);
            }
            if (options_.rate_mbps > 0) {
                // Limited throughput: time to send n bytes at the given rate.
                timer.expires_after(std::chrono::microseconds(static_cast<long long>(static_cast<double>(n) * 8 / options_.rate_mbps)));
                co_await timer.async_wait(use_tuple);
            }
            auto [wec, w] = co_await asio::async_write(to, asio::buffer(buffer.data(), n), use_tuple);
            (void)w;
            if (wec) {
                from.close(ignored);
                co_return;
            }
        }
    }

    asio::awaitable<void> cutter() {
        for (;;) {
            cut_timer_.expires_after(options_.cut_every);
            auto [ec] = co_await cut_timer_.async_wait(use_tuple);
            if (ec) co_return;
            cut_all(options_.freeze);
        }
    }

    // Cuts (RST) or silences the current connections.
    void cut_all(bool freeze) {
        std::list<std::shared_ptr<Link>> links;
        {
            std::lock_guard lock(mutex_);
            links.swap(links_);
        }
        for (auto& link : links) {
            asio::post(link->in.get_executor(), [link, freeze] {
                if (freeze) {
                    link->frozen = true;
                    return;
                }
                std::error_code ignored;
                link->in.set_option(asio::socket_base::linger(true, 0), ignored);
                link->out.set_option(asio::socket_base::linger(true, 0), ignored);
                link->in.close(ignored);
                link->out.close(ignored);
            });
        }
        if (!links.empty()) {
            std::cout << (freeze ? "silent link on " : "cut of ") << links.size() << " connection(s)" << '\n' << std::flush;
        }
    }

    asio::io_context& io_;
    tcp::acceptor acceptor_;
    tcp::endpoint target_;
    ProxyOptions options_;
    asio::steady_timer cut_timer_;
    std::mutex mutex_;
    std::list<std::shared_ptr<Link>> links_;
};

}  // namespace

int run_proxy(const tcp::endpoint& listen, const tcp::endpoint& target, const ProxyOptions& options, unsigned threads) {
    asio::io_context io;
    Proxy proxy(io, listen, target, options);
    proxy.start();
    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](std::error_code, int) {
        proxy.stop();
        io.stop();
    });
    run_threads(io, threads);
    return 0;
}

}  // namespace testkit
