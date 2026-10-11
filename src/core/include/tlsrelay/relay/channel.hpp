#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/relay/dial.hpp"
#include "tlsrelay/relay/stats.hpp"
#include "tlsrelay/relay/stream.hpp"
#include "tlsrelay/tls/context.hpp"

#include <asio/any_io_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace tlsrelay::relay {

enum class CloseReason { normal, idle_timeout, shutdown, dial_failed, tls_failed, io_error };

std::string_view to_string(CloseReason r);

struct ChannelSettings {
    PortKind port = PortKind::plain;
    Duration idle_timeout{};
    DialOptions dial;
    Duration handshake_timeout{};
    std::shared_ptr<const tls::Context> inbound_tls;   // mode serveur : TLS sur la connexion entrante
    std::shared_ptr<const tls::Context> outbound_tls;  // mode client : TLS sur la connexion sortante
    std::string server_name;                           // mode client : nom vérifié dans le certificat du serveur
};

// Un canal relaie une connexion entrante vers une connexion sortante, dans les
// deux sens, jusqu'à la fin des deux sens, une erreur, l'inactivité ou un abandon.
// Tout l'état est manipulé sur le strand de la socket entrante.
class Channel : public std::enable_shared_from_this<Channel> {
public:
    using ClosedCallback = std::function<void(std::uint64_t id)>;

    // inbound doit être associée à un strand : il sert d'exécuteur au canal.
    Channel(std::uint64_t id, asio::ip::tcp::socket inbound, ChannelSettings settings, Stats& stats,
            ClosedCallback on_closed);

    void start();

    // Ferme le canal immédiatement. Utilisable depuis n'importe quel thread.
    void abort(CloseReason reason);

    std::uint64_t id() const { return id_; }

private:
    using Clock = std::chrono::steady_clock;

    asio::awaitable<void> run();
    asio::awaitable<bool> secure(Stream& stream, std::string_view side);
    asio::awaitable<void> pump(Stream& from, Stream& to, std::uint64_t& bytes);
    asio::awaitable<void> watchdog();
    void fail(CloseReason reason, const std::error_code& ec);
    void close_streams();
    void finish();

    const std::uint64_t id_;
    asio::any_io_executor executor_;
    ChannelSettings settings_;
    std::unique_ptr<Stream> inbound_;
    std::unique_ptr<Stream> outbound_;
    Stats& stats_;
    ClosedCallback on_closed_;

    asio::steady_timer idle_timer_;
    asio::cancellation_signal dial_cancel_;
    Clock::time_point opened_at_;
    Clock::time_point last_activity_;
    std::optional<CloseReason> reason_;
    std::string peer_;
    std::uint64_t bytes_up_ = 0;
    std::uint64_t bytes_down_ = 0;
};

}  // namespace tlsrelay::relay
