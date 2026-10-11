#pragma once

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
#include <unordered_map>
#include <vector>

namespace tlsrelay::relay {

struct ServiceOptions {
    bool handle_signals = true;  // Ctrl+C / SIGTERM : arrêt propre ; second signal : arrêt immédiat
    unsigned threads = 0;        // 0 : nombre de cœurs
    Duration watch_interval = std::chrono::seconds(2);  // surveillance de la liste blanche et de la PKI
};

// Le service ouvre les ports configurés et relaie chaque connexion acceptée
// (mode client : vers l'upstream du port ; mode serveur : vers la destination).
// En mode serveur, il applique la liste blanche et la recharge quand son
// fichier change. Quand le fichier <pki_root>/current désigne une nouvelle
// génération, il bascule à chaud : les nouvelles connexions utilisent la
// nouvelle génération, les connexions ouvertes finissent sur l'ancienne
// (SPEC §7.4).
class Service : private PeerAuthorizer {
public:
    // Charge la PKI si un port TLS est configuré, puis ouvre les ports d'écoute.
    // Lève std::system_error si un port ne peut pas être ouvert,
    // std::runtime_error si la PKI est invalide ou si la configuration demande
    // une fonctionnalité absente de cette version.
    explicit Service(Config config, ServiceOptions options = {});
    ~Service() override;

    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;

    // Exécute le service jusqu'à son arrêt. Retourne le code de sortie.
    int run();

    // Arrêt propre : plus aucune connexion acceptée, drain des canaux pendant
    // limits.shutdown_timeout, puis fermeture des canaux restants.
    void request_stop();

    // Arrêt immédiat, sans drain.
    void request_abort();

    // Recharge la PKI (nouvelle génération désignée par current) et la liste
    // blanche, comme SIGHUP. kill_old : ferme aussi les connexions établies avec
    // une génération retirée. Utilisable depuis n'importe quel thread.
    void reload(bool kill_old = false);

    // Génération PKI courante (vide sans port TLS) et générations encore
    // utilisées par des connexions (courante comprise).
    std::string current_generation() const;
    std::vector<std::string> live_generations() const;

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

    struct Contexts {
        std::shared_ptr<const tls::Context> tls;   // port tls
        std::shared_ptr<const tls::Context> mtls;  // port mtls
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
    void load_whitelist();
    void reload_whitelist();
    std::optional<std::string> read_whitelist_file() const;
    std::shared_ptr<const whitelist::Whitelist> current_whitelist() const;
    std::optional<std::string> authorize(const asio::ip::address& address, PortKind port,
                                         const X509_NAME* subject) const override;
    asio::awaitable<void> watch();
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

    // PKI : génération courante, ses contextes, et générations retirées en drain.
    mutable std::mutex pki_mutex_;
    std::shared_ptr<const pki::Generation> generation_;
    Contexts contexts_;
    std::vector<RetiredGeneration> retired_;
    std::optional<std::string> pki_pointer_;  // contenu de current, accédé sur control_ après le démarrage

    mutable std::mutex whitelist_mutex_;
    std::shared_ptr<const whitelist::Whitelist> whitelist_;
    std::optional<std::string> whitelist_content_;  // accédé uniquement sur control_ après le démarrage
    asio::steady_timer watch_timer_;

    mutable std::mutex channels_mutex_;
    std::unordered_map<std::uint64_t, std::weak_ptr<Channel>> channels_;
    std::atomic<std::uint64_t> next_id_{1};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> aborting_{false};
    Stats stats_;
};

}  // namespace tlsrelay::relay
