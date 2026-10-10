#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/relay/dial.hpp"
#include "tlsrelay/relay/stats.hpp"

#include <asio/awaitable.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

namespace tlsrelay::relay {

enum class CloseReason { normal, idle_timeout, shutdown, dial_failed, io_error };

std::string_view to_string(CloseReason r);

struct ChannelSettings {
    PortKind port = PortKind::plain;
    Duration idle_timeout{};
    DialOptions dial;
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
    asio::awaitable<void> pump(asio::ip::tcp::socket& from, asio::ip::tcp::socket& to, std::uint64_t& bytes);
    asio::awaitable<void> watchdog();
    void fail(CloseReason reason, const std::error_code& ec);
    void close_sockets();
    void finish();

    const std::uint64_t id_;
    asio::ip::tcp::socket inbound_;
    std::optional<asio::ip::tcp::socket> outbound_;
    ChannelSettings settings_;
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
