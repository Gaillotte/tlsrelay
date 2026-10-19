#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/relay/dial.hpp"
#include "tlsrelay/relay/stats.hpp"
#include "tlsrelay/relay/stream.hpp"
#include "tlsrelay/relay/transport.hpp"
#include "tlsrelay/tls/context.hpp"
#include "tlsrelay/tunnel/frame.hpp"

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace tlsrelay::relay {

enum class CloseReason {
    normal,
    idle_timeout,
    shutdown,
    dial_failed,
    tls_failed,
    not_authorized,
    peer_revoked,
    certificate_revoked,
    generation_retired,
    io_error,
    lifetime_exceeded,  // no successful renegotiation within the grace period
    protocol_error,     // malformed frame received
    resume_refused,     // the server refused the session resumption
    closed_by_peer,     // CLOSE (code other than NORMAL) or OPEN_FAIL received
    internal_error
};

std::string_view to_string(CloseReason r);

// Decides whether a peer is authorized, according to the current whitelist (server mode).
class PeerAuthorizer {
public:
    virtual ~PeerAuthorizer() = default;
    // Returns the name of the entry that authorizes the peer, or std::nullopt.
    // subject: subject of the client certificate (mtls port), nullptr otherwise.
    virtual std::optional<std::string> authorize(const asio::ip::address& address, PortKind port,
                                                 const X509_NAME* subject) const = 0;
};

// tlsrelay peer authenticated on a transport connection (server mode).
struct PeerIdentity {
    asio::ip::address address;
    tls::X509NamePtr subject;  // client certificate (mtls port)
    std::string name;          // whitelist entry that authorizes the peer
    std::string endpoint;      // address:port, for the logs
};

enum class Side { client, server };

// State of a channel for the "channels" administration command.
struct ChannelInfo {
    std::uint64_t id = 0;
    PortKind port = PortKind::plain;
    std::string state;       // opening, open, renegotiating, resuming, closing
    std::string session;     // first 8 hexadecimal characters
    std::string peer;        // client: application; server: whitelist entry and address
    std::string generation;  // PKI generation of the current transport connection
    std::uint32_t transport = 0;  // number of the current transport connection
    std::chrono::milliseconds age{};
    std::chrono::milliseconds idle{};
    std::uint64_t bytes_up = 0;
    std::uint64_t bytes_down = 0;
    std::string flow;  // flow control: sequences, pending bytes, blocked tasks
};

struct ChannelSettings {
    Side side = Side::client;
    PortKind port = PortKind::plain;
    Duration idle_timeout{};
    Duration handshake_timeout{};
    Duration keepalive_interval{};  // 0: no PING
    Duration session_lifetime{};
    double session_jitter = 0.0;
    Duration renegotiation_grace{};
    std::uint64_t resume_buffer = 4ULL << 20;
    // Client: transport connection to the upstream. Server: destination.
    DialOptions dial;
    // Client: TLS context of the current generation (reread on each transport connection).
    std::function<std::shared_ptr<const tls::Context>()> tls_context;
    std::string server_name;                     // client: name checked in the server certificate
    const PeerAuthorizer* authorizer = nullptr;  // server: whitelist
};

// A channel links a "raw" connection (client: application; server:
// destination) to a tunnel to the other tlsrelay (SPEC §4). The tunnel goes
// through a series of transport connections: when session_lifetime expires,
// the client opens a new one (full handshake, current PKI generation)
// and resumes the session on it without loss or duplication of data.
//
// All state is handled on a strand, the channel's executor.
class Channel : public std::enable_shared_from_this<Channel> {
public:
    using ClosedCallback = std::function<void(Channel&)>;

    Channel(std::uint64_t id, asio::any_io_executor strand, ChannelSettings settings, Stats& stats,
            ClosedCallback on_closed);

    // Client: relays the application connection (socket on the channel's strand).
    void start_client(asio::ip::tcp::socket application);
    // Server: OPEN received on transport (already authenticated); connects to the destination.
    void start_server(std::shared_ptr<Transport> transport, const tunnel::SessionId& session, PeerIdentity peer);

    // Server: RESUME received on a new transport connection. To be run
    // on the channel's strand. On success, the channel takes the connection and
    // replies RESUMED on it; otherwise the caller replies RESUME_FAIL.
    asio::awaitable<bool> accept_resume(std::shared_ptr<Transport> transport, tunnel::Resume request,
                                        PeerIdentity peer, PortKind port);

    // Closes the channel (notifying the other tlsrelay). Usable from any thread.
    void abort(CloseReason reason);

    // Checks the peer again after a whitelist change; the
    // channel is closed if it is no longer authorized. Usable from any thread.
    void revalidate();

    // Closes the channel if its transport connection uses a context other than
    // the given ones (retired generation). Usable from any thread.
    void close_if_retired(std::shared_ptr<const tls::Context> tls, std::shared_ptr<const tls::Context> mtls);
    // Closes the channel if the peer certificate is listed in the CRLs in force.
    void close_if_revoked();

    // To be run on the channel's strand.
    asio::awaitable<ChannelInfo> describe() const;

    std::uint64_t id() const { return id_; }
    const asio::any_io_executor& executor() const { return executor_; }
    const tunnel::SessionId& session() const { return session_; }
    // After closing: reason and resumption token of the last connection.
    CloseReason close_reason() const { return reason_.value_or(CloseReason::normal); }
    const std::optional<tunnel::Token>& resume_token() const { return token_; }

private:
    using Clock = std::chrono::steady_clock;

    // Signal to a single waiter, remembered if nobody is waiting for it.
    class Event {
    public:
        explicit Event(const asio::any_io_executor& ex);
        void notify();
        asio::awaitable<void> wait();

    private:
        asio::steady_timer timer_;
        bool signaled_ = false;
    };

    struct Pending {
        std::uint64_t seq;
        std::string frame;  // encoded DATA frame
        std::size_t size;   // payload size
    };

    void spawn(asio::awaitable<void> task);
    asio::awaitable<void> run_client();
    asio::awaitable<void> run_server();
    // Client: new transport connection (TCP, then TLS with the current generation).
    asio::awaitable<std::shared_ptr<Transport>> connect_transport(std::string& failure, CloseReason& reason);

    asio::awaitable<void> sender();
    asio::awaitable<void> uplink();
    asio::awaitable<void> downlink();
    asio::awaitable<void> ack_loop();
    asio::awaitable<void> deliverer();
    asio::awaitable<void> watchdog();
    asio::awaitable<void> lifetime();
    asio::awaitable<void> keepalive();
    asio::awaitable<void> migrate();
    asio::awaitable<void> reopen();
    asio::awaitable<void> goodbye(std::shared_ptr<Transport> transport, std::string frame);
    asio::awaitable<void> retire(std::shared_ptr<Transport> transport);

    // Handles a received frame; false if the channel must stop.
    asio::awaitable<bool> handle(const tunnel::Frame& frame);
    asio::awaitable<bool> handle_data(const tunnel::Frame& frame);
    bool handle_ack(std::uint64_t seq);
    asio::awaitable<bool> deliver_peer_shutdown();
    void check_finished();

    bool install_transport(std::shared_ptr<Transport> transport);
    bool switch_transport(std::shared_ptr<Transport> transport, std::uint64_t peer_last_rx);
    void transport_failed(const std::shared_ptr<Transport>& transport, std::string_view what);
    void send_control(std::string frame);
    void send_ack();
    Duration next_lifetime();
    bool resumable() const;

    void protocol_error(tunnel::CloseCode code, const std::string& detail);
    // Closes the channel. last_frame: farewell frame; by default, CLOSE with the reason's code.
    void stop(CloseReason reason, std::optional<std::string> last_frame = std::nullopt);
    void finish();

    const std::uint64_t id_;
    asio::any_io_executor executor_;
    ChannelSettings settings_;
    Stats& stats_;
    ClosedCallback on_closed_;
    const Side side_;

    std::shared_ptr<Stream> raw_;  // client: application; server: destination
    std::string raw_peer_;
    tunnel::SessionId session_{};
    PeerIdentity peer_;  // server

    // Current transport connection (n = transport_index_) and resumption token.
    std::shared_ptr<Transport> transport_;
    std::uint32_t transport_index_ = 0;
    std::optional<tunnel::Token> token_;
    Clock::time_point transport_since_;
    Duration transport_lifetime_{};          // client: deadline drawn for the current connection
    std::optional<Clock::time_point> broken_since_;  // transport lost, resumption expected
    std::shared_ptr<Stream> pending_stream_;  // client: connection being opened
    bool migrating_ = false;
    bool opened_ = false;  // OPEN_OK sent (server) or received (client)
    int open_attempts_ = 0;  // client: reopenings of the tunnel before OPEN_OK

    // Sending: control frames, then unacknowledged DATA (resent after a resumption).
    std::deque<std::string> control_;
    std::deque<Pending> unacked_;
    std::uint64_t unacked_bytes_ = 0;
    std::uint64_t next_seq_ = 1;
    std::uint64_t sent_upto_ = 0;  // last seq written on the current connection
    bool local_shutdown_ = false;  // end of the raw source: SHUTDOWN_WR(final_seq_)
    std::uint64_t final_seq_ = 0;
    bool shutdown_sent_ = false;   // SHUTDOWN_WR written on the current connection

    // Reception. Received DATA waits for its delivery in delivery_: reading
    // the transport (ACK, PING…) does not depend on the application.
    struct Received {
        std::uint64_t seq;
        std::string bytes;
    };
    std::deque<Received> delivery_;
    std::uint64_t delivery_bytes_ = 0;
    std::uint64_t received_ = 0;  // last DATA received (queued)
    std::uint64_t last_rx_ = 0;   // last DATA delivered (acknowledged)
    std::uint64_t acked_rx_ = 0;
    std::uint64_t rx_since_ack_ = 0;  // bytes received since the last ACK
    std::optional<std::uint64_t> peer_final_;
    bool raw_shutdown_ = false;

    Event send_event_;
    Event space_event_;
    Event transport_event_;
    Event ack_event_;
    Event delivery_event_;  // DATA queued
    Event drained_event_;   // delivery queue drained
    asio::steady_timer idle_timer_;
    asio::steady_timer ack_timer_;
    asio::steady_timer lifetime_timer_;
    asio::steady_timer retry_timer_;
    asio::steady_timer keepalive_timer_;
    Clock::time_point last_frame_;  // last frame received on the current connection
    std::uint64_t ping_nonce_ = 0;
    bool reading_held_ = false;  // transport read suspended: delivery queue full
    bool window_full_ = false;   // source read suspended: resumption buffer full
    bool delivering_ = false;    // write to the raw connection in progress
    bool sending_ = false;       // send on the transport connection in progress
    bool reading_source_ = false;     // read of the raw connection in progress
    bool reading_transport_ = false;  // read of the transport connection in progress
    asio::cancellation_signal dial_cancel_;

    Clock::time_point opened_at_;
    Clock::time_point last_activity_;
    bool closing_ = false;
    bool finished_ = false;
    int tasks_ = 0;
    std::optional<CloseReason> reason_;
    std::uint64_t raw_in_ = 0;   // bytes read on the raw connection
    std::uint64_t raw_out_ = 0;  // bytes written on the raw connection
};

}  // namespace tlsrelay::relay
