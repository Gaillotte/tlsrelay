#include "tlsrelay/relay/channel.hpp"

#include "tlsrelay/logging.hpp"
#include "tlsrelay/whitelist.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <variant>

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
        case CloseReason::tls_failed: return "tls_refuse";
        case CloseReason::not_authorized: return "non_autorise";
        case CloseReason::peer_revoked: return "pair_retire";
        case CloseReason::io_error: return "erreur_reseau";
    }
    return "?";
}

Channel::Channel(std::uint64_t id, tcp::socket inbound, ChannelSettings settings, Stats& stats, ClosedCallback on_closed)
    : id_(id),
      executor_(inbound.get_executor()),
      settings_(std::move(settings)),
      stats_(stats),
      on_closed_(std::move(on_closed)),
      idle_timer_(executor_) {
    peer_ = describe_peer(inbound);
    std::error_code ec;
    const auto remote = inbound.remote_endpoint(ec);
    if (!ec) peer_address_ = whitelist::normalize(remote.address());
    inbound_ = settings_.inbound_tls ? std::make_unique<Stream>(std::move(inbound), settings_.inbound_tls)
                                     : std::make_unique<Stream>(std::move(inbound));
}

void Channel::start() {
    asio::co_spawn(executor_, [self = shared_from_this()] { return self->run(); }, asio::detached);
}

void Channel::abort(CloseReason reason) {
    asio::post(executor_, [self = shared_from_this(), reason] { self->stop(reason); });
}

void Channel::revalidate() {
    asio::post(executor_, [self = shared_from_this()] {
        // Pair pas encore authentifié : le contrôle après handshake utilisera la nouvelle liste.
        if (!self->settings_.authorizer || !self->peer_name_ || self->reason_) return;
        const auto name =
            self->settings_.authorizer->authorize(self->peer_address_, self->settings_.port, self->peer_subject_.get());
        if (name) {
            self->peer_name_ = name;
            return;
        }
        ++self->stats_.peers_revoked;
        logging::activity().info("canal={} pair « {} » retiré de la liste blanche : fermeture du canal", self->id_,
                                 *self->peer_name_);
        self->stop(CloseReason::peer_revoked);
    });
}

void Channel::stop(CloseReason reason) {
    if (!reason_) reason_ = reason;
    dial_cancel_.emit(asio::cancellation_type::terminal);
    idle_timer_.cancel();
    close_streams();
}

bool Channel::authorize_peer() {
    const X509_NAME* subject = nullptr;
    if (settings_.port == PortKind::mtls) {
        if (X509* cert = inbound_->peer_certificate()) {
            peer_subject_.reset(X509_NAME_dup(X509_get_subject_name(cert)));
            subject = peer_subject_.get();
        }
    }
    peer_name_ = settings_.authorizer->authorize(peer_address_, settings_.port, subject);
    if (!peer_name_) {
        ++stats_.peers_rejected;
        reason_ = CloseReason::not_authorized;
        logging::activity().info("canal={} pair refusé par la liste blanche : ip={} port={}{}", id_, peer_,
                                 to_string(settings_.port),
                                 subject ? " sujet=" + tls::name_to_string(subject) : std::string());
        return false;
    }
    logging::activity().debug("canal={} pair autorisé : « {} »", id_, *peer_name_);
    return true;
}

asio::awaitable<void> Channel::run() {
    opened_at_ = Clock::now();
    ++stats_.channels_opened;
    logging::activity().debug("canal={} ouvert port={} pair={} cible={}", id_, to_string(settings_.port), peer_,
                              settings_.dial.target.to_string());

    std::error_code ignored;
    inbound_->socket().set_option(tcp::no_delay(true), ignored);

    // Mode serveur : le pair doit s'authentifier avant toute connexion à la destination.
    if (inbound_->is_tls() && !co_await secure(*inbound_, "entrant")) {
        close_streams();
        finish();
        co_return;
    }
    // Liste blanche : en mTLS, l'IP et le sujet du certificat doivent figurer dans la même entrée.
    if (settings_.authorizer && !reason_ && !authorize_peer()) {
        close_streams();
        finish();
        co_return;
    }

    auto outbound = co_await asio::co_spawn(
        executor_, dial(settings_.dial, id_, stats_),
        asio::bind_cancellation_slot(dial_cancel_.slot(), asio::use_awaitable));

    if (reason_ || !outbound) {
        if (!reason_) reason_ = CloseReason::dial_failed;
        close_streams();
        finish();
        co_return;
    }
    // Relais : chaque bloc est transmis sans attendre (pas d'algorithme de Nagle).
    outbound->set_option(tcp::no_delay(true), ignored);
    outbound_ = settings_.outbound_tls
                    ? std::make_unique<Stream>(std::move(*outbound), settings_.outbound_tls, settings_.server_name)
                    : std::make_unique<Stream>(std::move(*outbound));

    // Mode client : vérification du serveur tlsrelay.
    if (outbound_->is_tls() && !co_await secure(*outbound_, "sortant")) {
        close_streams();
        finish();
        co_return;
    }

    last_activity_ = Clock::now();
    co_await ((pump(*inbound_, *outbound_, bytes_up_) && pump(*outbound_, *inbound_, bytes_down_)) || watchdog());

    if (!reason_) reason_ = CloseReason::normal;
    close_streams();
    finish();
}

asio::awaitable<bool> Channel::secure(Stream& stream, std::string_view side) {
    asio::steady_timer timer(executor_);
    timer.expires_after(settings_.handshake_timeout);
    auto result = co_await (stream.handshake() || timer.async_wait(use_tuple));

    if (reason_) co_return false;  // abandon pendant le handshake
    std::string failure;
    if (result.index() == 1) {
        failure = "délai de handshake dépassé (" + format_duration(settings_.handshake_timeout) + ")";
    } else if (const auto ec = std::get<0>(result)) {
        failure = stream.failure_reason().empty() ? ec.message() : stream.failure_reason();
    }
    if (!failure.empty()) {
        reason_ = CloseReason::tls_failed;
        ++stats_.tls_handshake_failures;
        logging::activity().info("canal={} handshake TLS {} refusé pair={} : {}", id_, side, peer_, failure);
        co_return false;
    }
    const auto subject = stream.peer_subject();
    logging::activity().debug("canal={} TLS {} établi : {}, certificat du pair : {}", id_, side,
                              stream.session_description(), subject.empty() ? "aucun" : subject);
    co_return true;
}

asio::awaitable<void> Channel::pump(Stream& from, Stream& to, std::uint64_t& bytes) {
    std::array<char, kBufferSize> buffer;
    for (;;) {
        auto [rec, n] = co_await from.read_some(asio::buffer(buffer));
        if (rec) {
            if (rec == asio::error::eof) {
                // Fin de ce sens : on la propage, l'autre sens continue.
                co_await to.shutdown_send();
            } else {
                fail(CloseReason::io_error, rec);
            }
            co_return;
        }
        last_activity_ = Clock::now();
        bytes += n;

        if (auto wec = co_await to.write(asio::buffer(buffer.data(), n))) {
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
            // Fermer les flux termine les deux sens sans dépendre de l'annulation.
            close_streams();
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
    close_streams();
}

void Channel::close_streams() {
    inbound_->close();
    if (outbound_) outbound_->close();
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
