#pragma once

#include "tlsrelay/admin/admin.hpp"
#include "tlsrelay/config.hpp"
#include "tlsrelay/relay/channel.hpp"
#include "tlsrelay/relay/stats.hpp"
#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/tls/context.hpp"
#include "tlsrelay/whitelist.hpp"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tlsrelay::relay {

struct ServiceOptions {
    bool handle_signals = true;  // Ctrl+C / SIGTERM: graceful shutdown; second signal: immediate shutdown
    unsigned threads = 0;        // 0: number of cores
    Duration watch_interval = std::chrono::seconds(2);  // watching of the whitelist and the PKI
    // Log output used instead of "stderr" (Windows service without a
    // console); also applied when the configuration is reread.
    std::string stderr_log_replacement{};
    std::string config_path{};  // file reread by the reload command (empty: no reread)
};

// The service opens the configured ports. In client mode, each application
// connection becomes a channel tunneled to the port's upstream; in server
// mode, each opened tunnel (OPEN) becomes a channel to the destination,
// and session resumptions (RESUME) join their channel (SPEC §4).
// In server mode, it applies the whitelist and reloads it when its
// file changes. When the file <pki_root>/current designates a new
// generation, it switches live: new connections use the
// new generation, open connections finish on the old one
// (SPEC §7.4).
//
// If admin.enabled, the service opens the administration channel (SPEC §10), which
// also serves as the instance lock.
class Service : private PeerAuthorizer, private admin::Handler {
public:
    // Loads the PKI if a TLS port is configured, then opens the listening ports.
    // Throws std::system_error if a port cannot be opened,
    // std::runtime_error if the PKI is invalid or if the configuration requests
    // a feature missing from this version.
    explicit Service(Config config, ServiceOptions options = {});
    ~Service() override;

    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    // Runs the service until it stops. Returns the exit code.
    int run();

    // Graceful shutdown: no more connections accepted, channels drained for
    // limits.shutdown_timeout, then the remaining channels are closed.
    void request_stop();
    void request_stop(Duration timeout);

    // Immediate shutdown, without drain.
    void request_abort();

    // Reloads the PKI (new generation designated by current) and the
    // whitelist, like SIGHUP. kill_old: also closes the connections established with
    // a retired generation. Usable from any thread.
    void reload(bool kill_old = false);

    // Current PKI generation (empty without a TLS port) and generations still
    // used by connections (current included).
    std::string current_generation() const;
    std::vector<std::string> live_generations() const;

    // Access point of the administration channel (empty if disabled).
    std::string admin_endpoint() const { return admin_ ? admin_->endpoint() : std::string(); }

    // Contents of the administration commands.
    std::string status_text() const;
    std::string metrics_text() const;

    std::optional<asio::ip::tcp::endpoint> local_endpoint(PortKind kind) const;
    std::size_t active_channels() const;
    const Stats& stats() const { return stats_; }

private:
    struct Port {
        Port(PortKind k, PortConfig c, asio::ip::tcp::acceptor a)
            : kind(k), config(std::move(c)), acceptor(std::move(a)) {}

        PortKind kind;
        PortConfig config;
        asio::ip::tcp::acceptor acceptor;
        std::atomic<std::size_t> active{0};      // channels
        std::atomic<std::size_t> handshakes{0};  // server: transport connections not yet assigned
    };

    struct Contexts {
        std::shared_ptr<const tls::Context> tls;   // tls port
        std::shared_ptr<const tls::Context> mtls;  // mtls port
    };
    struct RetiredGeneration {
        std::string name;
        std::weak_ptr<const tls::Context> tls;
        std::weak_ptr<const tls::Context> mtls;
        bool released() const { return tls.expired() && mtls.expired(); }
    };

    void load_pki();
    Contexts build_contexts(const std::shared_ptr<const pki::Generation>& generation) const;
    void reload_pki(bool kill_old);
    void close_retired_generations();
    void sweep_generations();
    std::optional<std::string> read_pki_pointer() const;
    // CRL (SPEC §7.7): <pki_root>/crl.pem checked for the given generation.
    // initial: at startup, an invalid file is a fatal error.
    bool load_crl(const pki::Generation& generation, bool initial);
    bool verifies_peers() const;
    std::optional<std::string> read_crl_file() const;
    void load_whitelist();
    bool reload_whitelist();
    std::optional<std::string> read_whitelist_file() const;
    std::shared_ptr<const whitelist::Whitelist> current_whitelist() const;
    std::optional<std::string> authorize(const asio::ip::address& address, PortKind port,
                                         const X509_NAME* subject) const override;
    asio::awaitable<void> watch();
    asio::awaitable<admin::Reply> handle(admin::Request request, std::string caller) override;
    asio::awaitable<std::string> reload_now(bool kill_old);
    asio::awaitable<std::string> channels_text();
    std::string reload_config();
    asio::awaitable<void> accept_loop(Port& port);
    // Server: authenticates a transport connection, then opens a channel
    // (OPEN) or hands it to the channel whose session it resumes (RESUME).
    asio::awaitable<void> serve(Port& port, asio::ip::tcp::socket socket, std::uint64_t id);
    asio::awaitable<void> drain(Duration timeout);
    asio::awaitable<void> wait_signals();
    ChannelSettings settings_for(const Port& port) const;
    void abort_all_channels();
    void on_channel_closed(Port& port, Channel& channel);
    std::vector<std::shared_ptr<Channel>> channels() const;

    Config config_;
    ServiceOptions options_;
    asio::io_context io_;
    asio::strand<asio::io_context::executor_type> control_;  // shutdown and signals
    std::list<Port> ports_;  // stable addresses: referenced by the accept loops
    asio::signal_set signals_;
    bool signals_done_ = false;  // accessed only on control_
    std::optional<asio::ip::address> source_address_;

    // PKI: current generation, its contexts, and retired generations being drained.
    mutable std::mutex pki_mutex_;
    std::shared_ptr<const pki::Generation> generation_;
    Contexts contexts_;
    std::vector<RetiredGeneration> retired_;
    std::optional<std::string> pki_pointer_;  // content of current, accessed on control_ after startup
    std::shared_ptr<tls::Revocations> revocations_ = std::make_shared<tls::Revocations>();
    std::optional<std::string> crl_content_;  // content of crl.pem, accessed on control_ after startup

    mutable std::mutex whitelist_mutex_;
    std::shared_ptr<const whitelist::Whitelist> whitelist_;
    std::optional<std::string> whitelist_content_;  // accessed only on control_ after startup
    asio::steady_timer watch_timer_;

    mutable std::mutex channels_mutex_;
    std::unordered_map<std::uint64_t, std::weak_ptr<Channel>> channels_;
    std::unordered_map<std::string, std::weak_ptr<Channel>> sessions_;      // server: by session_id (hex)
    std::unordered_map<std::uint64_t, std::weak_ptr<Stream>> handshakes_;   // server: pending connections
    // Server: sessions finished normally, kept during renegotiation_grace
    // to answer a resumption whose connection lost the final acknowledgement.
    struct FinishedSession {
        tunnel::Token token;
        std::chrono::steady_clock::time_point expiry;
    };
    std::unordered_map<std::string, FinishedSession> finished_;
    std::list<std::pair<std::chrono::steady_clock::time_point, std::string>> finished_order_;
    std::atomic<std::uint64_t> next_id_{1};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> aborting_{false};
    Stats stats_;
    std::unique_ptr<admin::Server> admin_;
    std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    std::chrono::system_clock::time_point started_wall_ = std::chrono::system_clock::now();
};

}  // namespace tlsrelay::relay
