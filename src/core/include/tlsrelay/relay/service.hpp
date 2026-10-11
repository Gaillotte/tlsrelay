#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/relay/channel.hpp"
#include "tlsrelay/relay/stats.hpp"
#include "tlsrelay/tls/context.hpp"

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
#include <unordered_map>

namespace tlsrelay::relay {

struct ServiceOptions {
    bool handle_signals = true;  // Ctrl+C / SIGTERM : arrêt propre ; second signal : arrêt immédiat
    unsigned threads = 0;        // 0 : nombre de cœurs
};

// Le service ouvre les ports configurés et relaie chaque connexion acceptée
// (mode client : vers l'upstream du port ; mode serveur : vers la destination).
class Service {
public:
    // Charge la PKI si un port TLS est configuré, puis ouvre les ports d'écoute.
    // Lève std::system_error si un port ne peut pas être ouvert,
    // std::runtime_error si la PKI est invalide ou si la configuration demande
    // une fonctionnalité absente de cette version.
    explicit Service(Config config, ServiceOptions options = {});
    ~Service();

    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    // Exécute le service jusqu'à son arrêt. Retourne le code de sortie.
    int run();

    // Arrêt propre : plus aucune connexion acceptée, drain des canaux pendant
    // limits.shutdown_timeout, puis fermeture des canaux restants.
    void request_stop();

    // Arrêt immédiat, sans drain.
    void request_abort();

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
        std::atomic<std::size_t> active{0};
    };

    void load_pki();
    asio::awaitable<void> accept_loop(Port& port);
    asio::awaitable<void> drain(Duration timeout);
    asio::awaitable<void> wait_signals();
    ChannelSettings settings_for(const Port& port) const;
    void abort_all_channels();
    void on_channel_closed(Port& port, std::uint64_t id);

    Config config_;
    ServiceOptions options_;
    asio::io_context io_;
    asio::strand<asio::io_context::executor_type> control_;  // arrêt et signaux
    std::list<Port> ports_;  // adresses stables : référencées par les boucles d'acceptation
    asio::signal_set signals_;
    bool signals_done_ = false;  // accédé uniquement sur control_
    std::optional<asio::ip::address> source_address_;
    std::shared_ptr<const tls::Context> tls_context_;  // génération PKI courante

    mutable std::mutex channels_mutex_;
    std::unordered_map<std::uint64_t, std::weak_ptr<Channel>> channels_;
    std::atomic<std::uint64_t> next_id_{1};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> aborting_{false};
    Stats stats_;
};

}  // namespace tlsrelay::relay
