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

constexpr std::uint64_t kAckBytes = 64ULL * 1024;        // immediate ACK beyond this (SPEC §4.4)
constexpr auto kAckDelay = 100ms;                      // otherwise, ACK after this delay
constexpr std::size_t kFlushBytes = 256ULL * 1024;       // DATA written before yielding
constexpr auto kGoodbyeTimeout = 1s;                   // sending of the last frame
constexpr auto kRetryFirst = 250ms;                    // renegotiation: first delay between attempts
constexpr auto kRetryMax = 5s;
constexpr int kOpenAttempts = 3;                       // reopenings of the tunnel before OPEN_OK

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
        case CloseReason::peer_revoked:
        case CloseReason::certificate_revoked: return CloseCode::peer_revoked;
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
        case CloseReason::idle_timeout: return "idle_timeout";
        case CloseReason::shutdown: return "shutdown";
        case CloseReason::dial_failed: return "destination_unreachable";
        case CloseReason::tls_failed: return "tls_refused";
        case CloseReason::not_authorized: return "not_authorized";
        case CloseReason::peer_revoked: return "peer_removed";
        case CloseReason::certificate_revoked: return "certificate_revoked";
        case CloseReason::generation_retired: return "generation_retired";
        case CloseReason::io_error: return "network_error";
        case CloseReason::lifetime_exceeded: return "lifetime_exceeded";
        case CloseReason::protocol_error: return "protocol_error";
        case CloseReason::resume_refused: return "resume_refused";
        case CloseReason::closed_by_peer: return "closed_by_peer";
        case CloseReason::internal_error: return "internal_error";
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
// Startup

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
      delivery_event_(executor_),
      drained_event_(executor_),
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
                               logging::activity().error("channel={} unexpected exception: {}", self->id_, ex.what());
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
        logging::activity().error("channel={} cannot generate the session identifier", id_);
        stop(CloseReason::internal_error);
        co_return;
    }
    logging::activity().debug("channel={} opened port={} application={} session={} upstream={}", id_,
                              to_string(settings_.port), raw_peer_, tunnel::to_hex(session_.data(), session_.size()),
                              settings_.dial.target.to_string());
    // The application may write before OPEN_OK: its data waits in the send queue.
    spawn(uplink());
    spawn(watchdog());

    std::shared_ptr<Transport> transport;
    for (;;) {
        std::string failure;
        CloseReason failure_reason = CloseReason::dial_failed;
        transport = co_await connect_transport(failure, failure_reason);
        if (closing_) co_return;
        if (transport) break;
        // Connection lost during the handshake: same rule as a loss before
        // OPEN_OK (the send queue waits); a refusal is not retried.
        if (failure_reason == CloseReason::io_error && open_attempts_ < kOpenAttempts) {
            ++open_attempts_;
            logging::activity().info("channel={} tunnel to {} failed ({}): new attempt {}/{}", id_,
                                     settings_.dial.target.to_string(), failure, open_attempts_, kOpenAttempts);
            retry_timer_.expires_after(std::chrono::milliseconds(100) * open_attempts_);
            co_await retry_timer_.async_wait(use_tuple);
            if (closing_) co_return;
            continue;
        }
        logging::activity().info("channel={} tunnel to {} failed: {}", id_, settings_.dial.target.to_string(),
                                 failure);
        stop(failure_reason);
        co_return;
    }
    if (!install_transport(transport)) co_return;
    send_control(tunnel::encode_open({tunnel::kVersion, session_, settings_.port}));
    spawn(sender());
    spawn(downlink());
    spawn(ack_loop());
    spawn(deliverer());
    spawn(lifetime());
    spawn(keepalive());
}

// Client: new transport connection and new session after the loss of
// the previous one before OPEN_OK. The application data waits in
// the send queue (nothing was sent before OPEN_OK).
asio::awaitable<void> Channel::reopen() {
    retry_timer_.expires_after(std::chrono::milliseconds(100) * open_attempts_);
    co_await retry_timer_.async_wait(use_tuple);
    if (closing_) co_return;
    std::string failure;
    CloseReason failure_reason = CloseReason::dial_failed;
    auto transport = co_await connect_transport(failure, failure_reason);
    if (closing_) co_return;
    if (!transport) {
        if (failure_reason == CloseReason::io_error && open_attempts_ < kOpenAttempts) {
            ++open_attempts_;
            logging::activity().info("channel={} tunnel to {} failed ({}): new attempt {}/{}", id_,
                                     settings_.dial.target.to_string(), failure, open_attempts_, kOpenAttempts);
            spawn(reopen());
            co_return;
        }
        logging::activity().info("channel={} tunnel to {} failed: {}", id_, settings_.dial.target.to_string(),
                                 failure);
        stop(failure_reason);
        co_return;
    }
    if (RAND_bytes(session_.data(), static_cast<int>(session_.size())) != 1) {
        stop(CloseReason::internal_error);
        co_return;
    }
    transport_index_ = 0;  // new session: token of connection n=1
    control_.clear();
    if (!install_transport(std::move(transport))) co_return;
    send_control(tunnel::encode_open({tunnel::kVersion, session_, settings_.port}));
}

asio::awaitable<void> Channel::run_server() {
    opened_at_ = last_activity_ = Clock::now();
    logging::activity().debug("channel={} opened port={} peer=\"{}\" ({}) session={} destination={}", id_,
                              to_string(settings_.port), peer_.name, peer_.endpoint,
                              tunnel::to_hex(session_.data(), session_.size()), settings_.dial.target.to_string());
    spawn(watchdog());

    // The peer is authenticated and authorized: connect to the destination.
    auto socket = co_await asio::co_spawn(executor_, dial(settings_.dial, id_, stats_),
                                          asio::bind_cancellation_slot(dial_cancel_.slot(), asio::use_awaitable));
    if (closing_) co_return;
    if (!socket) {
        stop(CloseReason::dial_failed, tunnel::encode_open_fail(static_cast<std::uint16_t>(CloseCode::dest_unreachable),
                                                                "destination unreachable"));
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
    spawn(deliverer());
    spawn(lifetime());
    spawn(keepalive());
}

asio::awaitable<std::shared_ptr<Transport>> Channel::connect_transport(std::string& failure, CloseReason& reason) {
    std::shared_ptr<const tls::Context> context;
    if (settings_.port != PortKind::plain) {
        context = settings_.tls_context ? settings_.tls_context() : nullptr;
        if (!context) {
            failure = "TLS context unavailable";
            reason = CloseReason::internal_error;
            co_return nullptr;
        }
    }
    std::error_code dial_error;
    auto socket = co_await asio::co_spawn(executor_, dial(settings_.dial, id_, stats_, &dial_error),
                                          asio::bind_cancellation_slot(dial_cancel_.slot(), asio::use_awaitable));
    if (closing_) co_return nullptr;
    if (!socket) {
        failure = "TCP connection failed";
        // Connection accepted then cut at once: a cut, not a refusal.
        reason = dial_error == asio::error::connection_reset ? CloseReason::io_error : CloseReason::dial_failed;
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
            reason = stream->handshake_interrupted() ? CloseReason::io_error : CloseReason::tls_failed;
            failure = "TLS handshake refused: " + failure;
            stream->close();
            co_return nullptr;
        }
        logging::activity().debug("channel={} TLS established with {}: {}, generation {}, server certificate: {}", id_,
                                  settings_.dial.target.to_string(), stream->session_description(),
                                  stream->context()->generation().name, stream->peer_subject());
    }
    co_return std::make_shared<Transport>(std::move(stream));
}

// ---------------------------------------------------------------------------
// Current transport connection

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
            logging::activity().error("channel={} cannot derive the resumption token", id_);
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
    // The other side cannot have received data never sent. It may
    // however announce less than what it already acknowledged: an ACK sent
    // on the old connection after RESUME may have arrived before it. That
    // data is received; the resend starts after it.
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
    control_.clear();  // frames specific to the old connection
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
    logging::activity().debug("channel={} session resumed on connection n={} ({}); {} frame(s) to resend", id_,
                              transport_index_,
                              transport_->stream->context() ? transport_->stream->context()->generation().name
                                                            : std::string("plain"),
                              resent);
    return true;
}

void Channel::transport_failed(const std::shared_ptr<Transport>& transport, std::string_view what) {
    if (closing_ || transport != transport_ || transport->broken) return;
    transport->broken = true;
    transport->stream->close();
    // Client, before OPEN_OK: no application data has been sent
    // yet; the tunnel is reopened (new session) instead of failing.
    if (side_ == Side::client && !opened_ && open_attempts_ < kOpenAttempts) {
        ++open_attempts_;
        logging::activity().info("channel={} transport connection lost before the tunnel was opened ({}): "
                                 "new attempt {}/{}",
                                 id_, what, open_attempts_, kOpenAttempts);
        spawn(reopen());
        return;
    }
    if (!resumable() || !opened_) {
        logging::activity().debug("channel={} transport connection lost: {}", id_, what);
        stop(CloseReason::io_error);
        return;
    }
    // During a renegotiation, the server closes the old connection as soon as it resumes: this is expected.
    if (migrating_) {
        logging::activity().debug("channel={} transport connection n={} closed during the renegotiation ({})", id_,
                                  transport_index_, what);
    } else {
        logging::activity().info("channel={} transport connection n={} lost ({}): session resumption expected", id_,
                                 transport_index_, what);
    }
    broken_since_ = Clock::now();
    if (side_ == Side::client && !migrating_) {
        migrating_ = true;
        spawn(migrate());
    }
    lifetime_timer_.cancel();  // server: the deadline becomes the end of the grace period
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
// Loops

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
        if (!ec) {
            sending_ = true;
            ec = co_await t->stream->flush();
            sending_ = false;
        }
        if (ec) transport_failed(t, "send: " + ec.message());
    }
}

asio::awaitable<void> Channel::uplink() {
    std::vector<std::uint8_t> buffer(tunnel::kMaxData);
    while (!closing_) {
        // Back-pressure: the source is not read while the resumption buffer is full.
        if (unacked_bytes_ >= settings_.resume_buffer) {
            window_full_ = true;
            co_await space_event_.wait();
            window_full_ = false;
            continue;
        }
        reading_source_ = true;
        auto [ec, n] = co_await raw_->read_some(asio::buffer(buffer));
        reading_source_ = false;
        if (closing_) co_return;
        if (ec) {
            if (ec != asio::error::eof) {
                logging::activity().debug("channel={} read error on {}: {}", id_, raw_peer_, ec.message());
                stop(CloseReason::io_error);
                co_return;
            }
            // End of this direction: SHUTDOWN_WR after the last DATA frame.
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
        reading_transport_ = true;
        auto r = co_await read_frame(*t);
        reading_transport_ = false;
        if (closing_) co_return;
        if (t != transport_) continue;  // replaced during the read
        if (!r.frame) {
            if (r.protocol != tunnel::Decoder::Error::none) {
                protocol_error(r.protocol == tunnel::Decoder::Error::frame_too_large ? CloseCode::frame_too_large
                                                                                     : CloseCode::protocol_error,
                               t->decoder.error_detail());
                co_return;
            }
            transport_failed(t, r.error == asio::error::eof ? "closed by the peer" : r.error.message());
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
            // The client renegotiates at the latest at lifetime × (1 + jitter).
            deadline = transport_since_ + scale(settings_.session_lifetime, 1.0 + settings_.session_jitter) +
                       settings_.renegotiation_grace;
            if (broken_since_) deadline = std::min(*deadline, *broken_since_ + settings_.renegotiation_grace);
        }
        if (deadline && Clock::now() >= *deadline) {
            if (side_ == Side::client) {
                logging::activity().debug("channel={} connection n={} expired: renegotiation", id_,
                                          transport_index_);
                migrating_ = true;
                spawn(migrate());
                continue;
            }
            ++stats_.resume_failures;
            if (broken_since_) {
                logging::activity().info("channel={} no session resumption within the grace period ({}): closing",
                                         id_, format_duration(settings_.renegotiation_grace));
                stop(CloseReason::io_error);
            } else {
                logging::activity().info("channel={} no renegotiation within the grace period: closing", id_);
                stop(CloseReason::lifetime_exceeded);
            }
            co_return;
        }
        lifetime_timer_.expires_at(deadline.value_or(asio::steady_timer::time_point::max()));
        co_await lifetime_timer_.async_wait(use_tuple);
    }
}

// Detection of a dead transport without a TCP error (SPEC §4.2): PING when nothing
// has been received for one interval; after 3 intervals of silence, the
// connection is abandoned (session resumption on the TLS ports).
asio::awaitable<void> Channel::keepalive() {
    const auto interval = settings_.keepalive_interval;
    if (interval <= Duration::zero()) co_return;
    while (!closing_) {
        keepalive_timer_.expires_after(interval);
        co_await keepalive_timer_.async_wait(use_tuple);
        if (closing_) co_return;
        auto t = transport_;
        if (!t || t->broken || !opened_) continue;
        const auto silence = Clock::now() - last_frame_;
        // Delivery queue full (slow application), the transport is not
        // read: no verdict, but the PINGs continue so that the other side,
        // which receives nothing else, does not conclude the link is dead.
        if (silence >= 3 * interval && !reading_held_) {
            transport_failed(t, "no frame received for " +
                                    format_duration(std::chrono::duration_cast<Duration>(silence)));
        } else if (silence >= interval) {
            send_control(tunnel::encode_ping(++ping_nonce_));
        }
    }
}

// Client: opens connection n+1 and resumes the session on it. Data
// keeps flowing on connection n meanwhile.
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
                    protocol_error(CloseCode::protocol_error, "RESUMED: inconsistent last_rx_seq");
                    break;
                }
                ++stats_.renegotiations;
                break;
            }
            t->stream->close();
            if (!ec && r.frame && r.frame->type == FrameType::resume_fail) {
                const auto code = static_cast<CloseCode>(tunnel::read_code(*r.frame));
                if (code == CloseCode::normal && local_shutdown_) {
                    // The server received and delivered everything, and this side acknowledged everything
                    // it sent: only the end of the exchange (final ACK,
                    // SHUTDOWN_WR) was lost with the connection.
                    logging::activity().debug("channel={} session already finished by the server", id_);
                    unacked_.clear();
                    unacked_bytes_ = 0;
                    // Everything the server sent has been received: end of the downstream direction
                    // after the delivery in progress, if any.
                    while (!delivery_.empty() && !closing_) co_await drained_event_.wait();
                    if (closing_) break;
                    if (!peer_final_) peer_final_ = last_rx_;
                    co_await deliver_peer_shutdown();
                    if (!closing_) stop(CloseReason::normal);
                    break;
                }
                ++stats_.resume_failures;
                logging::activity().info("channel={} session resumption refused by the server: {}", id_,
                                         tunnel::to_string(code));
                stop(CloseReason::resume_refused);
                break;
            }
            failure = ec                                              ? ec.message()
                      : r.frame                                       ? "unexpected " + std::string(tunnel::to_string(r.frame->type)) + " frame"
                      : r.protocol != tunnel::Decoder::Error::none    ? t->decoder.error_detail()
                      : r.error == asio::error::timed_out             ? std::string("no reply to RESUME")
                                                                      : r.error.message();
        }
        const auto now = Clock::now();
        if (now >= deadline) {
            ++stats_.resume_failures;
            logging::activity().info("channel={} renegotiation failed within the grace period ({}): {}", id_,
                                     format_duration(settings_.renegotiation_grace), failure);
            stop(CloseReason::lifetime_exceeded);
            break;
        }
        logging::activity().debug("channel={} renegotiation: attempt failed ({}), new attempt in {}", id_, failure,
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
        refusal = "channel closing";
    } else if (!resumable() || port != settings_.port) {
        refusal = "port different from the channel's";
    } else if (!token_ || CRYPTO_memcmp(token_->data(), request.token.data(), token_->size()) != 0) {
        refusal = "invalid resumption token";
    } else if (peer.name != peer_.name) {
        refusal = "peer \"" + peer.name + "\" different from \"" + peer_.name + "\"";
    } else if (!switch_transport(transport, request.last_rx_seq)) {
        refusal = "inconsistent last_rx_seq";
    }
    if (!refusal.empty()) {
        ++stats_.resume_failures;
        logging::activity().info("channel={} session resumption refused ({}): {}", id_, peer.endpoint, refusal);
        co_return false;
    }
    peer_ = std::move(peer);
    // RESUMED precedes the resent DATA: control frames go first.
    control_.push_front(tunnel::encode_resumed(last_rx_));
    acked_rx_ = last_rx_;
    rx_since_ack_ = 0;
    send_event_.notify();
    ++stats_.renegotiations;
    co_return true;
}

// ---------------------------------------------------------------------------
// Reception

asio::awaitable<bool> Channel::handle(const tunnel::Frame& f) {
    switch (f.type) {
        case FrameType::data: co_return co_await handle_data(f);
        case FrameType::ack: co_return handle_ack(tunnel::read_u64(f));
        case FrameType::shutdown_wr: {
            const auto final_seq = tunnel::read_u64(f);
            if (final_seq < received_ || (peer_final_ && *peer_final_ != final_seq)) {
                protocol_error(CloseCode::protocol_error, "inconsistent SHUTDOWN_WR");
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
                logging::activity().info("channel={} closed by the other tlsrelay: {} {}", id_,
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
                logging::activity().debug("channel={} tunnel open", id_);
                send_event_.notify();
                co_return true;
            }
            break;
        case FrameType::open_fail:
            if (side_ == Side::client && !opened_) {
                const auto status = tunnel::read_status(f);
                const auto code = static_cast<CloseCode>(status.code);
                logging::activity().info("channel={} opening refused by the server: {} {}", id_,
                                         tunnel::to_string(code), status.message);
                stop(code == CloseCode::dest_unreachable ? CloseReason::dial_failed : CloseReason::closed_by_peer,
                     std::string());
                co_return false;
            }
            break;
        default: break;
    }
    protocol_error(CloseCode::protocol_error, "unexpected " + std::string(tunnel::to_string(f.type)) + " frame");
    co_return false;
}

asio::awaitable<bool> Channel::handle_data(const tunnel::Frame& f) {
    if (!opened_) {
        protocol_error(CloseCode::protocol_error, "DATA before OPEN_OK");
        co_return false;
    }
    const auto d = tunnel::read_data(f);
    if (d.seq <= received_) co_return true;  // already received: resend after a resumption
    if (d.seq != received_ + 1 || (peer_final_ && d.seq > *peer_final_)) {
        protocol_error(CloseCode::protocol_error,
                       "DATA seq=" + std::to_string(d.seq) + " instead of " + std::to_string(received_ + 1));
        co_return false;
    }
    // The sender never has more than resume_buffer + kMaxData unacknowledged bytes
    // (it stops once resume_buffer is reached): the queue only fills beyond that
    // if the two sides are configured differently; reading then waits for
    // the delivery.
    while (delivery_bytes_ + d.size > settings_.resume_buffer + tunnel::kMaxData && !closing_) {
        reading_held_ = true;
        co_await drained_event_.wait();
    }
    if (reading_held_) last_frame_ = Clock::now();  // silence during the wait does not count
    reading_held_ = false;
    if (closing_) co_return false;
    received_ = d.seq;
    delivery_.push_back(Received{d.seq, std::string(reinterpret_cast<const char*>(d.bytes), d.size)});
    delivery_bytes_ += d.size;
    delivery_event_.notify();
    co_return true;
}

// Delivery of the received DATA to the raw connection, in order; the acknowledgement
// follows the delivery (acknowledged data has been written).
asio::awaitable<void> Channel::deliverer() {
    while (!closing_) {
        if (delivery_.empty()) {
            co_await delivery_event_.wait();
            continue;
        }
        // Pending DATA goes out in a single write (kFlushBytes at most):
        // full segments rather than one small segment per frame. A destination
        // that stops reading would otherwise exhaust its receive buffer (memory cost
        // of each segment) before its window closes: the kernel then drops
        // segments and the connection bogs down in retransmissions.
        std::size_t count = 0;
        std::size_t size = 0;
        std::error_code ec;
        while (!ec && count < delivery_.size() &&
               (count == 0 || size + delivery_[count].bytes.size() <= kFlushBytes)) {
            ec = raw_->queue(asio::buffer(delivery_[count].bytes));
            size += delivery_[count].bytes.size();
            ++count;
        }
        delivering_ = true;
        if (!ec) ec = co_await raw_->flush();
        delivering_ = false;
        if (closing_) co_return;
        if (ec) {
            logging::activity().debug("channel={} write error to {}: {}", id_, raw_peer_, ec.message());
            stop(CloseReason::io_error);
            co_return;
        }
        const auto seq = delivery_[count - 1].seq;
        delivery_.erase(delivery_.begin(), delivery_.begin() + static_cast<std::ptrdiff_t>(count));
        delivery_bytes_ -= size;
        drained_event_.notify();
        last_rx_ = seq;
        raw_out_ += size;
        last_activity_ = Clock::now();
        rx_since_ack_ += size;
        if (rx_since_ack_ >= kAckBytes) send_ack();
        else ack_event_.notify();
        if (!co_await deliver_peer_shutdown()) co_return;
    }
}

bool Channel::handle_ack(std::uint64_t seq) {
    if (seq >= next_seq_) {
        protocol_error(CloseCode::protocol_error, "ACK of data never sent");
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
    send_ack();  // the other side learns without waiting that everything is delivered
    check_finished();
    co_return !closing_;
}

void Channel::check_finished() {
    // Both directions are finished and everything sent is acknowledged.
    if (!closing_ && local_shutdown_ && unacked_.empty() && raw_shutdown_) stop(CloseReason::normal);
}

asio::awaitable<ChannelInfo> Channel::describe() const {
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    ChannelInfo info;
    info.id = id_;
    info.port = settings_.port;
    info.state = closing_                ? "closing"
                 : !opened_              ? "opening"
                 : broken_since_         ? "resuming"
                 : migrating_            ? "renegotiating"
                                         : "open";
    info.session = tunnel::to_hex(session_.data(), 4);
    info.peer = side_ == Side::client ? raw_peer_ : "\"" + peer_.name + "\" " + peer_.endpoint;
    if (transport_ && transport_->stream->context()) info.generation = transport_->stream->context()->generation().name;
    info.transport = transport_index_;
    const auto now = Clock::now();
    info.age = duration_cast<milliseconds>(now - opened_at_);
    info.idle = duration_cast<milliseconds>(now - last_activity_);
    info.bytes_up = side_ == Side::client ? raw_in_ : raw_out_;
    info.bytes_down = side_ == Side::client ? raw_out_ : raw_in_;
    std::string blocked;
    if (window_full_) blocked += ",window";
    if (sending_) blocked += ",sending";
    if (delivering_) blocked += ",delivering";
    if (reading_held_) blocked += ",read_held";
    if (reading_source_) blocked += ",reading_source";
    if (reading_transport_) blocked += ",reading_transport";
    info.flow = "produced=" + std::to_string(next_seq_ - 1) + " sent=" + std::to_string(sent_upto_) +
                " unacked=" + std::to_string(unacked_bytes_) + "B received=" + std::to_string(received_) +
                " delivered=" + std::to_string(last_rx_) + " acked=" + std::to_string(acked_rx_) +
                " queue=" + std::to_string(delivery_bytes_) + "B busy=" + (blocked.empty() ? "-" : blocked.substr(1));
    co_return info;
}

// ---------------------------------------------------------------------------
// Closing

void Channel::abort(CloseReason reason) {
    asio::post(executor_, [self = shared_from_this(), reason] { self->stop(reason); });
}

void Channel::revalidate() {
    asio::post(executor_, [self = shared_from_this()] {
        // Peer not yet authenticated, or channel closing.
        if (!self->settings_.authorizer || self->peer_.name.empty() || self->closing_) return;
        const auto name = self->settings_.authorizer->authorize(self->peer_.address, self->settings_.port,
                                                                self->peer_.subject.get());
        if (name) {
            self->peer_.name = *name;
            return;
        }
        ++self->stats_.peers_revoked;
        logging::activity().info("channel={} peer \"{}\" removed from the whitelist: closing the channel", self->id_,
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

void Channel::close_if_revoked() {
    asio::post(executor_, [self = shared_from_this()] {
        if (self->closing_ || !self->transport_) return;
        const auto& stream = *self->transport_->stream;
        const auto* ctx = stream.context();
        if (!ctx || !ctx->is_revoked(stream.peer_certificate())) return;
        ++self->stats_.certificates_revoked;
        logging::activity().info("channel={} peer certificate revoked ({}): closing the channel", self->id_,
                                 stream.peer_subject());
        self->stop(CloseReason::certificate_revoked);
    });
}

void Channel::protocol_error(CloseCode code, const std::string& detail) {
    ++stats_.protocol_errors;
    logging::activity().info("channel={} protocol error: {}", id_, detail);
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
    delivery_event_.notify();
    drained_event_.notify();
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

// cppcheck-suppress passedByValue ; coroutine: the frame must live in the coroutine frame
asio::awaitable<void> Channel::goodbye(std::shared_ptr<Transport> t, std::string frame) {
    // Pending control frames (ACK...), then the last frame.
    std::string out;
    for (const auto& c : control_) out += c;
    control_.clear();
    out += frame;
    if (!out.empty()) {
        if (const auto ec = t->stream->queue(asio::buffer(out))) {
            logging::activity().debug("channel={} last frame not sent: {}", id_, ec.message());
        }
    }
    co_await retire(std::move(t));
}

// Graceful close of a transport connection (close_notify), bounded in time.
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

    logging::activity().debug("channel={} closed reason={} up={}B down={}B connections={} duration={}ms", id_,
                              to_string(reason), up, down, transport_index_, duration.count());
    // Releases the connections, hence the PKI generations they use.
    transport_.reset();
    raw_.reset();
    pending_stream_.reset();
    if (on_closed_) on_closed_(*this);
}

}  // namespace tlsrelay::relay
