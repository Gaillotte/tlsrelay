#include "tlsrelay/relay/channel.hpp"

#include "tlsrelay/logging.hpp"
#include "tlsrelay/whitelist.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/bind_executor.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <exception>
#include <random>
#include <vector>

namespace tlsrelay::relay {
namespace {

using asio::ip::tcp;
using namespace std::chrono_literals;
using tunnel::CloseCode;
using tunnel::FrameType;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

constexpr std::uint64_t kAckBytes = 64ULL * 1024;        // ACK immédiat au-delà (SPEC §4.4)
constexpr auto kAckDelay = 100ms;                      // sinon, ACK après ce délai
constexpr std::size_t kFlushBytes = 256ULL * 1024;       // DATA écrites avant de rendre la main
constexpr auto kGoodbyeTimeout = 1s;                   // envoi de la dernière trame
constexpr auto kRetryFirst = 250ms;                    // renégociation : premier délai entre essais
constexpr auto kRetryMax = 5s;

std::string describe_peer(const tcp::socket& s) {
    std::error_code ec;
    const auto ep = s.remote_endpoint(ec);
    if (ec) return "?";
    return Endpoint{ep.address().to_string(), ep.port()}.to_string();
}

CloseCode code_for(CloseReason r) {
    switch (r) {
        case CloseReason::normal:
        case CloseReason::closed_by_peer: return CloseCode::normal;
        case CloseReason::idle_timeout: return CloseCode::idle_timeout;
        case CloseReason::shutdown:
        case CloseReason::generation_retired: return CloseCode::shutdown;
        case CloseReason::dial_failed: return CloseCode::dest_unreachable;
        case CloseReason::not_authorized:
        case CloseReason::resume_refused: return CloseCode::not_authorized;
        case CloseReason::peer_revoked: return CloseCode::peer_revoked;
        case CloseReason::lifetime_exceeded: return CloseCode::lifetime_exceeded;
        case CloseReason::protocol_error: return CloseCode::protocol_error;
        case CloseReason::tls_failed:
        case CloseReason::io_error:
        case CloseReason::internal_error: return CloseCode::internal_error;
    }
    return CloseCode::internal_error;
}

double random_factor(double jitter) {
    if (jitter <= 0) return 1.0;
    thread_local std::mt19937_64 engine{std::random_device{}()};
    return std::uniform_real_distribution<double>(1.0 - jitter, 1.0 + jitter)(engine);
}

Duration scale(Duration d, double factor) {
    return std::chrono::duration_cast<Duration>(
        std::chrono::duration<double, Duration::period>(static_cast<double>(d.count()) * factor));
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
        case CloseReason::generation_retired: return "generation_retiree";
        case CloseReason::io_error: return "erreur_reseau";
        case CloseReason::lifetime_exceeded: return "duree_de_vie_depassee";
        case CloseReason::protocol_error: return "erreur_protocole";
        case CloseReason::resume_refused: return "reprise_refusee";
        case CloseReason::closed_by_peer: return "ferme_par_le_pair";
        case CloseReason::internal_error: return "erreur_interne";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Event

Channel::Event::Event(const asio::any_io_executor& ex) : timer_(ex) {}

void Channel::Event::notify() {
    signaled_ = true;
    timer_.cancel();
}

asio::awaitable<void> Channel::Event::wait() {
    if (!signaled_) {
        timer_.expires_at(asio::steady_timer::time_point::max());
        co_await timer_.async_wait(use_tuple);
    }
    signaled_ = false;
}

// ---------------------------------------------------------------------------
// Démarrage

Channel::Channel(std::uint64_t id, asio::any_io_executor strand, ChannelSettings settings, Stats& stats,
                 ClosedCallback on_closed)
    : id_(id),
      executor_(std::move(strand)),
      settings_(std::move(settings)),
      stats_(stats),
      on_closed_(std::move(on_closed)),
      side_(settings_.side),
      send_event_(executor_),
      space_event_(executor_),
      transport_event_(executor_),
      ack_event_(executor_),
      idle_timer_(executor_),
      ack_timer_(executor_),
      lifetime_timer_(executor_),
      retry_timer_(executor_),
      keepalive_timer_(executor_),
      opened_at_(Clock::now()),
      last_activity_(opened_at_) {}

void Channel::start_client(tcp::socket application) {
    raw_peer_ = describe_peer(application);
    std::error_code ignored;
    application.set_option(tcp::no_delay(true), ignored);
    raw_ = std::make_shared<Stream>(std::move(application));
    ++stats_.channels_opened;
    asio::post(executor_, [self = shared_from_this()] { self->spawn(self->run_client()); });
}

void Channel::start_server(std::shared_ptr<Transport> transport, const tunnel::SessionId& session, PeerIdentity peer) {
    session_ = session;
    peer_ = std::move(peer);
    ++stats_.channels_opened;
    asio::post(executor_, [self = shared_from_this(), transport = std::move(transport)]() mutable {
        if (!self->install_transport(std::move(transport))) return;
        self->spawn(self->run_server());
    });
}

void Channel::spawn(asio::awaitable<void> task) {
    ++tasks_;
    asio::co_spawn(executor_, std::move(task),
                   asio::bind_executor(executor_, [self = shared_from_this()](const std::exception_ptr& e) {
                       if (e) {
                           try {
                               std::rethrow_exception(e);
                           } catch (const std::exception& ex) {
                               logging::activity().error("canal={} exception inattendue : {}", self->id_, ex.what());
                           }
                           self->stop(CloseReason::internal_error);
                       }
                       if (--self->tasks_ == 0 && self->closing_) self->finish();
                   }));
}

bool Channel::resumable() const { return settings_.port != PortKind::plain; }

Duration Channel::next_lifetime() { return scale(settings_.session_lifetime, random_factor(settings_.session_jitter)); }

asio::awaitable<void> Channel::run_client() {
    opened_at_ = last_activity_ = Clock::now();
    if (RAND_bytes(session_.data(), static_cast<int>(session_.size())) != 1) {
        logging::activity().error("canal={} génération de l'identifiant de session impossible", id_);
        stop(CloseReason::internal_error);
        co_return;
    }
    logging::activity().debug("canal={} ouvert port={} application={} session={} upstream={}", id_,
                              to_string(settings_.port), raw_peer_, tunnel::to_hex(session_.data(), session_.size()),
                              settings_.dial.target.to_string());
    // L'application peut écrire avant OPEN_OK : ses données attendent dans la file d'émission.
    spawn(uplink());
    spawn(watchdog());

    std::string failure;
    CloseReason failure_reason = CloseReason::dial_failed;
    auto transport = co_await connect_transport(failure, failure_reason);
    if (closing_) co_return;
    if (!transport) {
        logging::activity().info("canal={} tunnel vers {} impossible : {}", id_, settings_.dial.target.to_string(),
                                 failure);
        stop(failure_reason);
        co_return;
    }
    if (!install_transport(transport)) co_return;
    send_control(tunnel::encode_open({tunnel::kVersion, session_, settings_.port}));
    spawn(sender());
    spawn(downlink());
    spawn(ack_loop());
    spawn(lifetime());
    spawn(keepalive());
}

asio::awaitable<void> Channel::run_server() {
    opened_at_ = last_activity_ = Clock::now();
    logging::activity().debug("canal={} ouvert port={} pair=« {} » ({}) session={} destination={}", id_,
                              to_string(settings_.port), peer_.name, peer_.endpoint,
                              tunnel::to_hex(session_.data(), session_.size()), settings_.dial.target.to_string());
    spawn(watchdog());

    // Le pair est authentifié et autorisé : connexion à la destination.
    auto socket = co_await asio::co_spawn(executor_, dial(settings_.dial, id_, stats_),
                                          asio::bind_cancellation_slot(dial_cancel_.slot(), asio::use_awaitable));
    if (closing_) co_return;
    if (!socket) {
        stop(CloseReason::dial_failed, tunnel::encode_open_fail(static_cast<std::uint16_t>(CloseCode::dest_unreachable),
                                                                "destination injoignable"));
        co_return;
    }
    std::error_code ignored;
    socket->set_option(tcp::no_delay(true), ignored);
    raw_peer_ = describe_peer(*socket);
    raw_ = std::make_shared<Stream>(std::move(*socket));
    opened_ = true;
    send_control(tunnel::encode_open_ok());
    spawn(sender());
    spawn(downlink());
    spawn(uplink());
    spawn(ack_loop());
    spawn(lifetime());
    spawn(keepalive());
}

asio::awaitable<std::shared_ptr<Transport>> Channel::connect_transport(std::string& failure, CloseReason& reason) {
    std::shared_ptr<const tls::Context> context;
    if (settings_.port != PortKind::plain) {
        context = settings_.tls_context ? settings_.tls_context() : nullptr;
        if (!context) {
            failure = "contexte TLS indisponible";
            reason = CloseReason::internal_error;
            co_return nullptr;
        }
    }
    auto socket = co_await asio::co_spawn(executor_, dial(settings_.dial, id_, stats_),
                                          asio::bind_cancellation_slot(dial_cancel_.slot(), asio::use_awaitable));
    if (closing_) co_return nullptr;
    if (!socket) {
        failure = "connexion TCP impossible";
        reason = CloseReason::dial_failed;
        co_return nullptr;
    }
    std::error_code ignored;
    socket->set_option(tcp::no_delay(true), ignored);
    auto stream = context ? std::make_shared<Stream>(std::move(*socket), context, settings_.server_name)
                          : std::make_shared<Stream>(std::move(*socket));
    if (stream->is_tls()) {
        pending_stream_ = stream;
        failure = co_await secure(stream, settings_.handshake_timeout);
        pending_stream_.reset();
        if (closing_) {
            stream->close();
            co_return nullptr;
        }
        if (!failure.empty()) {
            ++stats_.tls_handshake_failures;
            reason = CloseReason::tls_failed;
            failure = "handshake TLS refusé : " + failure;
            stream->close();
            co_return nullptr;
        }
        logging::activity().debug("canal={} TLS établi avec {} : {}, génération {}, certificat du serveur : {}", id_,
                                  settings_.dial.target.to_string(), stream->session_description(),
                                  stream->context()->generation().name, stream->peer_subject());
    }
    co_return std::make_shared<Transport>(std::move(stream));
}

// ---------------------------------------------------------------------------
// Connexion de transport courante

bool Channel::install_transport(std::shared_ptr<Transport> transport) {
    transport_ = std::move(transport);
    ++transport_index_;
    transport_since_ = Clock::now();
    last_frame_ = transport_since_;
    transport_lifetime_ = next_lifetime();
    broken_since_.reset();
    if (resumable()) {
        token_ = derive_token(*transport_->stream, session_, transport_index_);
        if (!token_) {
            logging::activity().error("canal={} dérivation du jeton de reprise impossible", id_);
            stop(CloseReason::internal_error);
            return false;
        }
    }
    transport_event_.notify();
    send_event_.notify();
    lifetime_timer_.cancel();
    return true;
}

bool Channel::switch_transport(std::shared_ptr<Transport> transport, std::uint64_t peer_last_rx) {
    // L'autre côté ne peut pas avoir reçu des données jamais envoyées. Il peut
    // en revanche annoncer moins que ce qu'il a déjà acquitté : un ACK envoyé
    // sur l'ancienne connexion après RESUME a pu arriver avant lui. Ces
    // données-là sont reçues ; le renvoi commence après.
    if (peer_last_rx >= next_seq_) return false;
    const std::uint64_t first_unacked = unacked_.empty() ? next_seq_ : unacked_.front().seq;
    peer_last_rx = std::max(peer_last_rx, first_unacked - 1);
    while (!unacked_.empty() && unacked_.front().seq <= peer_last_rx) {
        unacked_bytes_ -= unacked_.front().size;
        unacked_.pop_front();
    }
    const std::uint64_t resent = next_seq_ - 1 - peer_last_rx;

    auto old = std::move(transport_);
    if (!install_transport(std::move(transport))) return false;
    sent_upto_ = peer_last_rx;
    control_.clear();  // trames propres à l'ancienne connexion
    shutdown_sent_ = false;
    if (old) {
        if (!old->broken) {
            old->broken = true;
            spawn(retire(old));
        } else {
            old->stream->close();
        }
    }
    space_event_.notify();
    logging::activity().debug("canal={} session reprise sur la connexion n={} ({}) ; {} trame(s) à renvoyer", id_,
                              transport_index_,
                              transport_->stream->context() ? transport_->stream->context()->generation().name
                                                            : std::string("clair"),
                              resent);
    return true;
}

void Channel::transport_failed(const std::shared_ptr<Transport>& transport, std::string_view what) {
    if (closing_ || transport != transport_ || transport->broken) return;
    transport->broken = true;
    transport->stream->close();
    if (!resumable() || !opened_) {
        logging::activity().debug("canal={} connexion de transport perdue : {}", id_, what);
        stop(CloseReason::io_error);
        return;
    }
    // Pendant une renégociation, le serveur ferme l'ancienne connexion dès la reprise : c'est attendu.
    if (migrating_) {
        logging::activity().debug("canal={} connexion de transport n={} fermée pendant la renégociation ({})", id_,
                                  transport_index_, what);
    } else {
        logging::activity().info("canal={} connexion de transport n={} perdue ({}) : reprise de session attendue", id_,
                                 transport_index_, what);
    }
    broken_since_ = Clock::now();
    if (side_ == Side::client && !migrating_) {
        migrating_ = true;
        spawn(migrate());
    }
    lifetime_timer_.cancel();  // serveur : l'échéance devient la fin du délai de grâce
}

void Channel::send_control(std::string frame) {
    control_.push_back(std::move(frame));
    send_event_.notify();
}

void Channel::send_ack() {
    if (last_rx_ > acked_rx_) {
        control_.push_back(tunnel::encode_ack(last_rx_));
        acked_rx_ = last_rx_;
        send_event_.notify();
    }
    rx_since_ack_ = 0;
}

// ---------------------------------------------------------------------------
// Boucles

asio::awaitable<void> Channel::sender() {
    while (!closing_) {
        auto t = transport_;
        if (!t || t->broken) {
            co_await send_event_.wait();
            continue;
        }
        bool any = false;
        std::error_code ec;
        while (!control_.empty() && !ec) {
            ec = t->stream->queue(asio::buffer(control_.front()));
            control_.pop_front();
            any = true;
        }
        if (opened_) {
            std::size_t queued = 0;
            while (!ec && queued < kFlushBytes && sent_upto_ + 1 < next_seq_) {
                const auto& p = unacked_[static_cast<std::size_t>(sent_upto_ + 1 - unacked_.front().seq)];
                ec = t->stream->queue(asio::buffer(p.frame));
                sent_upto_ = p.seq;
                queued += p.frame.size();
                any = true;
            }
            if (!ec && local_shutdown_ && !shutdown_sent_ && sent_upto_ + 1 == next_seq_) {
                ec = t->stream->queue(asio::buffer(tunnel::encode_shutdown_wr(final_seq_)));
                shutdown_sent_ = true;
                any = true;
            }
        }
        if (!any) {
            co_await send_event_.wait();
            continue;
        }
        if (!ec) ec = co_await t->stream->flush();
        if (ec) transport_failed(t, "émission : " + ec.message());
    }
}

asio::awaitable<void> Channel::uplink() {
    std::vector<std::uint8_t> buffer(tunnel::kMaxData);
    while (!closing_) {
        // Contre-pression : la source n'est plus lue tant que le tampon de reprise est plein.
        if (unacked_bytes_ >= settings_.resume_buffer) {
            co_await space_event_.wait();
            continue;
        }
        auto [ec, n] = co_await raw_->read_some(asio::buffer(buffer));
        if (closing_) co_return;
        if (ec) {
            if (ec != asio::error::eof) {
                logging::activity().debug("canal={} erreur de lecture sur {} : {}", id_, raw_peer_, ec.message());
                stop(CloseReason::io_error);
                co_return;
            }
            // Fin de ce sens : SHUTDOWN_WR après la dernière trame DATA.
            local_shutdown_ = true;
            final_seq_ = next_seq_ - 1;
            send_event_.notify();
            check_finished();
            co_return;
        }
        last_activity_ = Clock::now();
        raw_in_ += n;
        const std::uint64_t seq = next_seq_++;
        unacked_.push_back({seq, tunnel::encode_data(seq, buffer.data(), n), n});
        unacked_bytes_ += n;
        send_event_.notify();
    }
}

asio::awaitable<void> Channel::downlink() {
    while (!closing_) {
        auto t = transport_;
        if (!t || t->broken) {
            co_await transport_event_.wait();
            continue;
        }
        auto r = co_await read_frame(*t);
        if (closing_) co_return;
        if (t != transport_) continue;  // remplacée pendant la lecture
        if (!r.frame) {
            if (r.protocol != tunnel::Decoder::Error::none) {
                protocol_error(r.protocol == tunnel::Decoder::Error::frame_too_large ? CloseCode::frame_too_large
                                                                                     : CloseCode::protocol_error,
                               t->decoder.error_detail());
                co_return;
            }
            transport_failed(t, r.error == asio::error::eof ? "fermée par le pair" : r.error.message());
            continue;
        }
        last_frame_ = Clock::now();
        if (!co_await handle(*r.frame)) co_return;
    }
}

asio::awaitable<void> Channel::ack_loop() {
    while (!closing_) {
        co_await ack_event_.wait();
        if (closing_) co_return;
        ack_timer_.expires_after(kAckDelay);
        co_await ack_timer_.async_wait(use_tuple);
        if (closing_) co_return;
        send_ack();
    }
}

asio::awaitable<void> Channel::watchdog() {
    while (!closing_) {
        const auto deadline = last_activity_ + settings_.idle_timeout;
        if (Clock::now() >= deadline) {
            stop(CloseReason::idle_timeout);
            co_return;
        }
        idle_timer_.expires_at(deadline);
        co_await idle_timer_.async_wait(use_tuple);
    }
}

asio::awaitable<void> Channel::lifetime() {
    if (!resumable()) co_return;
    while (!closing_) {
        std::optional<Clock::time_point> deadline;
        if (side_ == Side::client) {
            if (!migrating_) deadline = transport_since_ + transport_lifetime_;
        } else {
            // Le client renégocie au plus tard à lifetime × (1 + jitter).
            deadline = transport_since_ + scale(settings_.session_lifetime, 1.0 + settings_.session_jitter) +
                       settings_.renegotiation_grace;
            if (broken_since_) deadline = std::min(*deadline, *broken_since_ + settings_.renegotiation_grace);
        }
        if (deadline && Clock::now() >= *deadline) {
            if (side_ == Side::client) {
                logging::activity().debug("canal={} échéance de la connexion n={} : renégociation", id_,
                                          transport_index_);
                migrating_ = true;
                spawn(migrate());
                continue;
            }
            ++stats_.resume_failures;
            if (broken_since_) {
                logging::activity().info("canal={} pas de reprise de session dans le délai de grâce ({}) : fermeture",
                                         id_, format_duration(settings_.renegotiation_grace));
                stop(CloseReason::io_error);
            } else {
                logging::activity().info("canal={} pas de renégociation dans le délai de grâce : fermeture", id_);
                stop(CloseReason::lifetime_exceeded);
            }
            co_return;
        }
        lifetime_timer_.expires_at(deadline.value_or(asio::steady_timer::time_point::max()));
        co_await lifetime_timer_.async_wait(use_tuple);
    }
}

// Détection d'un transport mort sans erreur TCP (SPEC §4.2) : PING quand rien
// n'a été reçu depuis un intervalle ; au bout de 3 intervalles de silence, la
// connexion est abandonnée (reprise de session sur les ports TLS).
asio::awaitable<void> Channel::keepalive() {
    const auto interval = settings_.keepalive_interval;
    if (interval <= Duration::zero()) co_return;
    while (!closing_) {
        keepalive_timer_.expires_after(interval);
        co_await keepalive_timer_.async_wait(use_tuple);
        if (closing_) co_return;
        auto t = transport_;
        // Pendant une livraison bloquée par l'application, le transport n'est pas lu : pas de verdict.
        if (!t || t->broken || !opened_ || delivering_) continue;
        const auto silence = Clock::now() - last_frame_;
        if (silence >= 3 * interval) {
            transport_failed(t, "aucune trame reçue depuis " +
                                    format_duration(std::chrono::duration_cast<Duration>(silence)));
        } else if (silence >= interval) {
            send_control(tunnel::encode_ping(++ping_nonce_));
        }
    }
}

// Client : ouvre la connexion n+1 et y reprend la session. Les données
// continuent de circuler sur la connexion n pendant ce temps.
asio::awaitable<void> Channel::migrate() {
    const auto deadline = Clock::now() + settings_.renegotiation_grace;
    Duration backoff = kRetryFirst;
    while (!closing_) {
        std::string failure;
        CloseReason ignored_reason{};
        auto t = co_await connect_transport(failure, ignored_reason);
        if (closing_) break;
        if (t) {
            pending_stream_ = t->stream;
            auto ec = t->stream->queue(asio::buffer(tunnel::encode_resume({session_, *token_, last_rx_})));
            if (!ec) ec = co_await t->stream->flush();
            FrameRead r;
            if (!ec && !closing_) r = co_await read_frame(*t, settings_.handshake_timeout);
            pending_stream_.reset();
            if (closing_) {
                t->stream->close();
                break;
            }
            if (!ec && r.frame && r.frame->type == FrameType::resumed) {
                if (!switch_transport(t, tunnel::read_u64(*r.frame))) {
                    t->stream->close();
                    protocol_error(CloseCode::protocol_error, "RESUMED : last_rx_seq incohérent");
                    break;
                }
                ++stats_.renegotiations;
                break;
            }
            t->stream->close();
            if (!ec && r.frame && r.frame->type == FrameType::resume_fail) {
                const auto code = static_cast<CloseCode>(tunnel::read_code(*r.frame));
                ++stats_.resume_failures;
                logging::activity().info("canal={} reprise de session refusée par le serveur : {}", id_,
                                         tunnel::to_string(code));
                stop(CloseReason::resume_refused);
                break;
            }
            failure = ec                                              ? ec.message()
                      : r.frame                                       ? "trame " + std::string(tunnel::to_string(r.frame->type)) + " inattendue"
                      : r.protocol != tunnel::Decoder::Error::none    ? t->decoder.error_detail()
                      : r.error == asio::error::timed_out             ? std::string("pas de réponse à RESUME")
                                                                      : r.error.message();
        }
        const auto now = Clock::now();
        if (now >= deadline) {
            ++stats_.resume_failures;
            logging::activity().info("canal={} renégociation impossible dans le délai de grâce ({}) : {}", id_,
                                     format_duration(settings_.renegotiation_grace), failure);
            stop(CloseReason::lifetime_exceeded);
            break;
        }
        logging::activity().debug("canal={} renégociation : essai échoué ({}), nouvel essai dans {}", id_, failure,
                                  format_duration(backoff));
        retry_timer_.expires_at(std::min(now + backoff, deadline));
        co_await retry_timer_.async_wait(use_tuple);
        backoff = std::min<Duration>(backoff * 2, kRetryMax);
    }
    migrating_ = false;
    lifetime_timer_.cancel();
}

asio::awaitable<bool> Channel::accept_resume(std::shared_ptr<Transport> transport, tunnel::Resume request,
                                             PeerIdentity peer, PortKind port) {
    std::string refusal;
    if (closing_ || finished_) {
        refusal = "canal en cours de fermeture";
    } else if (!resumable() || port != settings_.port) {
        refusal = "port différent de celui du canal";
    } else if (!token_ || CRYPTO_memcmp(token_->data(), request.token.data(), token_->size()) != 0) {
        refusal = "jeton de reprise invalide";
    } else if (peer.name != peer_.name) {
        refusal = "pair « " + peer.name + " » différent de « " + peer_.name + " »";
    } else if (!switch_transport(transport, request.last_rx_seq)) {
        refusal = "last_rx_seq incohérent";
    }
    if (!refusal.empty()) {
        ++stats_.resume_failures;
        logging::activity().info("canal={} reprise de session refusée ({}) : {}", id_, peer.endpoint, refusal);
        co_return false;
    }
    peer_ = std::move(peer);
    // RESUMED précède les DATA renvoyées : les trames de contrôle passent en premier.
    control_.push_front(tunnel::encode_resumed(last_rx_));
    acked_rx_ = last_rx_;
    rx_since_ack_ = 0;
    send_event_.notify();
    ++stats_.renegotiations;
    co_return true;
}

// ---------------------------------------------------------------------------
// Réception

asio::awaitable<bool> Channel::handle(const tunnel::Frame& f) {
    switch (f.type) {
        case FrameType::data: co_return co_await handle_data(f);
        case FrameType::ack: co_return handle_ack(tunnel::read_u64(f));
        case FrameType::shutdown_wr: {
            const auto final_seq = tunnel::read_u64(f);
            if (final_seq < last_rx_ || (peer_final_ && *peer_final_ != final_seq)) {
                protocol_error(CloseCode::protocol_error, "SHUTDOWN_WR incohérent");
                co_return false;
            }
            peer_final_ = final_seq;
            co_return co_await deliver_peer_shutdown();
        }
        case FrameType::close: {
            const auto status = tunnel::read_status(f);
            if (status.code == static_cast<std::uint16_t>(CloseCode::normal)) {
                stop(CloseReason::normal, std::string());
            } else {
                logging::activity().info("canal={} fermé par l'autre tlsrelay : {} {}", id_,
                                         tunnel::to_string(static_cast<CloseCode>(status.code)), status.message);
                stop(CloseReason::closed_by_peer, std::string());
            }
            co_return false;
        }
        case FrameType::ping: send_control(tunnel::encode_pong(tunnel::read_u64(f))); co_return true;
        case FrameType::pong: co_return true;
        case FrameType::open_ok:
            if (side_ == Side::client && !opened_) {
                opened_ = true;
                logging::activity().debug("canal={} tunnel ouvert", id_);
                send_event_.notify();
                co_return true;
            }
            break;
        case FrameType::open_fail:
            if (side_ == Side::client && !opened_) {
                const auto status = tunnel::read_status(f);
                const auto code = static_cast<CloseCode>(status.code);
                logging::activity().info("canal={} ouverture refusée par le serveur : {} {}", id_,
                                         tunnel::to_string(code), status.message);
                stop(code == CloseCode::dest_unreachable ? CloseReason::dial_failed : CloseReason::closed_by_peer,
                     std::string());
                co_return false;
            }
            break;
        default: break;
    }
    protocol_error(CloseCode::protocol_error, "trame " + std::string(tunnel::to_string(f.type)) + " inattendue");
    co_return false;
}

asio::awaitable<bool> Channel::handle_data(const tunnel::Frame& f) {
    if (!opened_) {
        protocol_error(CloseCode::protocol_error, "DATA avant OPEN_OK");
        co_return false;
    }
    const auto d = tunnel::read_data(f);
    if (d.seq <= last_rx_) co_return true;  // déjà reçue : renvoi après une reprise
    if (d.seq != last_rx_ + 1 || (peer_final_ && d.seq > *peer_final_)) {
        protocol_error(CloseCode::protocol_error,
                       "DATA seq=" + std::to_string(d.seq) + " au lieu de " + std::to_string(last_rx_ + 1));
        co_return false;
    }
    delivering_ = true;
    const auto ec = co_await raw_->write(asio::buffer(d.bytes, d.size));
    delivering_ = false;
    last_frame_ = Clock::now();  // le silence pendant la livraison ne compte pas
    if (closing_) co_return false;
    if (ec) {
        logging::activity().debug("canal={} erreur d'écriture vers {} : {}", id_, raw_peer_, ec.message());
        stop(CloseReason::io_error);
        co_return false;
    }
    // Acquittement après livraison : une donnée acquittée a été écrite.
    last_rx_ = d.seq;
    raw_out_ += d.size;
    last_activity_ = Clock::now();
    rx_since_ack_ += d.size;
    if (rx_since_ack_ >= kAckBytes) send_ack();
    else ack_event_.notify();
    co_return co_await deliver_peer_shutdown();
}

bool Channel::handle_ack(std::uint64_t seq) {
    if (seq >= next_seq_) {
        protocol_error(CloseCode::protocol_error, "ACK de données jamais envoyées");
        return false;
    }
    bool released = false;
    while (!unacked_.empty() && unacked_.front().seq <= seq) {
        unacked_bytes_ -= unacked_.front().size;
        unacked_.pop_front();
        released = true;
    }
    if (sent_upto_ < seq) sent_upto_ = seq;
    if (released) space_event_.notify();
    check_finished();
    return !closing_;
}

asio::awaitable<bool> Channel::deliver_peer_shutdown() {
    if (!peer_final_ || last_rx_ < *peer_final_ || raw_shutdown_) co_return true;
    raw_shutdown_ = true;
    co_await raw_->shutdown_send();
    if (closing_) co_return false;
    send_ack();  // l'autre côté apprend sans attendre que tout est livré
    check_finished();
    co_return !closing_;
}

void Channel::check_finished() {
    // Les deux sens sont terminés et tout ce qui a été envoyé est acquitté.
    if (!closing_ && local_shutdown_ && unacked_.empty() && raw_shutdown_) stop(CloseReason::normal);
}

asio::awaitable<ChannelInfo> Channel::describe() const {
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    ChannelInfo info;
    info.id = id_;
    info.port = settings_.port;
    info.state = closing_                ? "fermeture"
                 : !opened_              ? "ouverture"
                 : broken_since_         ? "reprise"
                 : migrating_            ? "renégociation"
                                         : "ouvert";
    info.session = tunnel::to_hex(session_.data(), 4);
    info.peer = side_ == Side::client ? raw_peer_ : "« " + peer_.name + " » " + peer_.endpoint;
    if (transport_ && transport_->stream->context()) info.generation = transport_->stream->context()->generation().name;
    info.transport = transport_index_;
    const auto now = Clock::now();
    info.age = duration_cast<milliseconds>(now - opened_at_);
    info.idle = duration_cast<milliseconds>(now - last_activity_);
    info.bytes_up = side_ == Side::client ? raw_in_ : raw_out_;
    info.bytes_down = side_ == Side::client ? raw_out_ : raw_in_;
    co_return info;
}

// ---------------------------------------------------------------------------
// Fermeture

void Channel::abort(CloseReason reason) {
    asio::post(executor_, [self = shared_from_this(), reason] { self->stop(reason); });
}

void Channel::revalidate() {
    asio::post(executor_, [self = shared_from_this()] {
        // Pair pas encore authentifié, ou canal en cours de fermeture.
        if (!self->settings_.authorizer || self->peer_.name.empty() || self->closing_) return;
        const auto name = self->settings_.authorizer->authorize(self->peer_.address, self->settings_.port,
                                                                self->peer_.subject.get());
        if (name) {
            self->peer_.name = *name;
            return;
        }
        ++self->stats_.peers_revoked;
        logging::activity().info("canal={} pair « {} » retiré de la liste blanche : fermeture du canal", self->id_,
                                 self->peer_.name);
        self->stop(CloseReason::peer_revoked);
    });
}

void Channel::close_if_retired(std::shared_ptr<const tls::Context> tls, std::shared_ptr<const tls::Context> mtls) {
    asio::post(executor_, [self = shared_from_this(), tls = std::move(tls), mtls = std::move(mtls)] {
        if (self->closing_ || !self->transport_) return;
        const auto* ctx = self->transport_->stream->context();
        if (ctx && ctx != tls.get() && ctx != mtls.get()) self->stop(CloseReason::generation_retired);
    });
}

void Channel::protocol_error(CloseCode code, const std::string& detail) {
    ++stats_.protocol_errors;
    logging::activity().info("canal={} erreur de protocole : {}", id_, detail);
    stop(CloseReason::protocol_error, tunnel::encode_close(static_cast<std::uint16_t>(code), detail));
}

void Channel::stop(CloseReason reason, std::optional<std::string> last_frame) {
    if (closing_) return;
    closing_ = true;
    reason_ = reason;
    dial_cancel_.emit(asio::cancellation_type::terminal);
    idle_timer_.cancel();
    ack_timer_.cancel();
    lifetime_timer_.cancel();
    retry_timer_.cancel();
    keepalive_timer_.cancel();
    send_event_.notify();
    space_event_.notify();
    transport_event_.notify();
    ack_event_.notify();
    if (raw_) raw_->close();
    if (pending_stream_) pending_stream_->close();

    if (auto t = transport_; t && !t->broken) {
        t->broken = true;
        if (!last_frame) {
            last_frame = tunnel::encode_close(static_cast<std::uint16_t>(code_for(reason)), to_string(reason));
        }
        spawn(goodbye(std::move(t), std::move(*last_frame)));
    } else if (t) {
        t->stream->close();
    }
    if (tasks_ == 0) finish();
}

// cppcheck-suppress passedByValue ; coroutine : la trame doit vivre dans son cadre
asio::awaitable<void> Channel::goodbye(std::shared_ptr<Transport> t, std::string frame) {
    // Trames de contrôle en attente (ACK...), puis la dernière trame.
    std::string out;
    for (const auto& c : control_) out += c;
    control_.clear();
    out += frame;
    if (!out.empty()) {
        if (const auto ec = t->stream->queue(asio::buffer(out))) {
            logging::activity().debug("canal={} dernière trame non envoyée : {}", id_, ec.message());
        }
    }
    co_await retire(std::move(t));
}

// Fermeture propre d'une connexion de transport (close_notify), bornée dans le temps.
asio::awaitable<void> Channel::retire(std::shared_ptr<Transport> t) {
    asio::steady_timer guard(executor_);
    guard.expires_after(kGoodbyeTimeout);
    guard.async_wait([stream = t->stream](std::error_code ec) {
        if (!ec) stream->close();
    });
    co_await t->stream->shutdown_send();
    guard.cancel();
    t->stream->close();
}

void Channel::finish() {
    if (finished_) return;
    finished_ = true;
    const auto reason = reason_.value_or(CloseReason::normal);
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - opened_at_);
    const auto up = side_ == Side::client ? raw_in_ : raw_out_;
    const auto down = side_ == Side::client ? raw_out_ : raw_in_;
    stats_.bytes_upstream += up;
    stats_.bytes_downstream += down;
    if (reason == CloseReason::idle_timeout) ++stats_.channels_idle_closed;
    ++stats_.channels_closed;

    logging::activity().debug("canal={} fermé raison={} montant={}o descendant={}o connexions={} durée={}ms", id_,
                              to_string(reason), up, down, transport_index_, duration.count());
    // Libère les connexions, donc les générations PKI qu'elles utilisent.
    transport_.reset();
    raw_.reset();
    pending_stream_.reset();
    if (on_closed_) on_closed_(*this);
}

}  // namespace tlsrelay::relay
