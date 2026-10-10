#include "tlsrelay/relay/channel.hpp"

#include "tlsrelay/logging.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <array>

namespace tlsrelay::relay {
namespace {

using asio::ip::tcp;
using namespace asio::experimental::awaitable_operators;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
constexpr std::size_t kBufferSize = 16 * 1024;

std::string describe_peer(const tcp::socket& s) {
    std::error_code ec;
    const auto ep = s.remote_endpoint(ec);
    if (ec) return "?";
    return Endpoint{ep.address().to_string(), ep.port()}.to_string();
}

}  // namespace

std::string_view to_string(CloseReason r) {
    switch (r) {
        case CloseReason::normal: return "normal";
        case CloseReason::idle_timeout: return "inactivite";
        case CloseReason::shutdown: return "arret";
        case CloseReason::dial_failed: return "destination_injoignable";
        case CloseReason::io_error: return "erreur_reseau";
    }
    return "?";
}

Channel::Channel(std::uint64_t id, tcp::socket inbound, ChannelSettings settings, Stats& stats, ClosedCallback on_closed)
    : id_(id),
      inbound_(std::move(inbound)),
      settings_(std::move(settings)),
      stats_(stats),
      on_closed_(std::move(on_closed)),
      idle_timer_(inbound_.get_executor()) {}

void Channel::start() {
    asio::co_spawn(inbound_.get_executor(), [self = shared_from_this()] { return self->run(); }, asio::detached);
}

void Channel::abort(CloseReason reason) {
    asio::post(inbound_.get_executor(), [self = shared_from_this(), reason] {
        if (!self->reason_) self->reason_ = reason;
        self->dial_cancel_.emit(asio::cancellation_type::terminal);
        self->idle_timer_.cancel();
        self->close_sockets();
    });
}

asio::awaitable<void> Channel::run() {
    opened_at_ = Clock::now();
    peer_ = describe_peer(inbound_);
    ++stats_.channels_opened;
    logging::activity().debug("canal={} ouvert port={} pair={} cible={}", id_, to_string(settings_.port), peer_,
                              settings_.dial.target.to_string());

    auto outbound = co_await asio::co_spawn(
        inbound_.get_executor(), dial(settings_.dial, id_, stats_),
        asio::bind_cancellation_slot(dial_cancel_.slot(), asio::use_awaitable));

    if (reason_) {  // abandon pendant la connexion sortante
        close_sockets();
        finish();
        co_return;
    }
    if (!outbound) {
        reason_ = CloseReason::dial_failed;
        close_sockets();
        finish();
        co_return;
    }
    outbound_.emplace(std::move(*outbound));
    // Relais : chaque bloc est transmis sans attendre (pas d'algorithme de Nagle).
    std::error_code ignored;
    inbound_.set_option(tcp::no_delay(true), ignored);
    outbound_->set_option(tcp::no_delay(true), ignored);
    last_activity_ = Clock::now();

    co_await ((pump(inbound_, *outbound_, bytes_up_) && pump(*outbound_, inbound_, bytes_down_)) || watchdog());

    if (!reason_) reason_ = CloseReason::normal;
    close_sockets();
    finish();
}

asio::awaitable<void> Channel::pump(tcp::socket& from, tcp::socket& to, std::uint64_t& bytes) {
    std::array<char, kBufferSize> buffer;
    for (;;) {
        auto [rec, n] = co_await from.async_read_some(asio::buffer(buffer), use_tuple);
        if (rec) {
            if (rec == asio::error::eof) {
                // Fin de ce sens : on la propage, l'autre sens continue.
                std::error_code ignored;
                to.shutdown(tcp::socket::shutdown_send, ignored);
            } else {
                fail(CloseReason::io_error, rec);
            }
            co_return;
        }
        last_activity_ = Clock::now();
        bytes += n;

        auto [wec, written] = co_await asio::async_write(to, asio::buffer(buffer.data(), n), use_tuple);
        (void)written;
        if (wec) {
            fail(CloseReason::io_error, wec);
            co_return;
        }
        last_activity_ = Clock::now();
    }
}

asio::awaitable<void> Channel::watchdog() {
    for (;;) {
        const auto deadline = last_activity_ + settings_.idle_timeout;
        if (Clock::now() >= deadline) {
            if (!reason_) reason_ = CloseReason::idle_timeout;
            // Fermer les sockets termine les deux sens sans dépendre de l'annulation.
            close_sockets();
            co_return;
        }
        idle_timer_.expires_at(deadline);
        co_await idle_timer_.async_wait(use_tuple);
        auto state = co_await asio::this_coro::cancellation_state;
        if (reason_ || state.cancelled() != asio::cancellation_type::none) co_return;
    }
}

void Channel::fail(CloseReason reason, const std::error_code& ec) {
    if (!reason_) {
        reason_ = reason;
        logging::activity().debug("canal={} erreur réseau : {}", id_, ec.message());
    }
    // Une erreur dans un sens termine aussi l'autre.
    close_sockets();
}

void Channel::close_sockets() {
    std::error_code ignored;
    inbound_.close(ignored);
    if (outbound_) outbound_->close(ignored);
}

void Channel::finish() {
    const auto reason = reason_.value_or(CloseReason::normal);
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - opened_at_);
    stats_.bytes_upstream += bytes_up_;
    stats_.bytes_downstream += bytes_down_;
    if (reason == CloseReason::idle_timeout) ++stats_.channels_idle_closed;
    ++stats_.channels_closed;

    logging::activity().debug("canal={} fermé raison={} montant={}o descendant={}o durée={}ms", id_, to_string(reason),
                              bytes_up_, bytes_down_, duration.count());
    if (on_closed_) on_closed_(id_);
}

}  // namespace tlsrelay::relay
