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
    generation_retired,
    io_error,
    lifetime_exceeded,  // pas de renégociation réussie dans le délai de grâce
    protocol_error,     // trame non conforme reçue
    resume_refused,     // le serveur a refusé la reprise de session
    closed_by_peer,     // CLOSE (code autre que NORMAL) ou OPEN_FAIL reçu
    internal_error
};

std::string_view to_string(CloseReason r);

// Décide si un pair est autorisé, selon la liste blanche courante (mode serveur).
class PeerAuthorizer {
public:
    virtual ~PeerAuthorizer() = default;
    // Retourne le nom de l'entrée qui autorise le pair, ou std::nullopt.
    // subject : sujet du certificat client (port mtls), nullptr sinon.
    virtual std::optional<std::string> authorize(const asio::ip::address& address, PortKind port,
                                                 const X509_NAME* subject) const = 0;
};

// Pair tlsrelay authentifié sur une connexion de transport (mode serveur).
struct PeerIdentity {
    asio::ip::address address;
    tls::X509NamePtr subject;  // certificat client (port mtls)
    std::string name;          // entrée de la liste blanche qui autorise le pair
    std::string endpoint;      // adresse:port, pour les journaux
};

enum class Side { client, server };

// État d'un canal pour la commande d'administration « channels ».
struct ChannelInfo {
    std::uint64_t id = 0;
    PortKind port = PortKind::plain;
    std::string state;       // ouverture, ouvert, renégociation, reprise, fermeture
    std::string session;     // 8 premiers caractères hexadécimaux
    std::string peer;        // client : application ; serveur : entrée de liste blanche et adresse
    std::string generation;  // génération PKI de la connexion de transport courante
    std::uint32_t transport = 0;  // numéro de la connexion de transport courante
    std::chrono::milliseconds age{};
    std::chrono::milliseconds idle{};
    std::uint64_t bytes_up = 0;
    std::uint64_t bytes_down = 0;
};

struct ChannelSettings {
    Side side = Side::client;
    PortKind port = PortKind::plain;
    Duration idle_timeout{};
    Duration handshake_timeout{};
    Duration keepalive_interval{};  // 0 : pas de PING
    Duration session_lifetime{};
    double session_jitter = 0.0;
    Duration renegotiation_grace{};
    std::uint64_t resume_buffer = 4ULL << 20;
    // Client : connexion de transport vers l'upstream. Serveur : destination.
    DialOptions dial;
    // Client : contexte TLS de la génération courante (relu à chaque connexion de transport).
    std::function<std::shared_ptr<const tls::Context>()> tls_context;
    std::string server_name;                     // client : nom vérifié dans le certificat du serveur
    const PeerAuthorizer* authorizer = nullptr;  // serveur : liste blanche
};

// Un canal relie une connexion « brute » (client : application ; serveur :
// destination) à un tunnel vers l'autre tlsrelay (SPEC §4). Le tunnel passe
// par une suite de connexions de transport : à l'échéance de session_lifetime,
// le client en ouvre une nouvelle (handshake complet, génération PKI courante)
// et y reprend la session sans perte ni duplication de données.
//
// Tout l'état est manipulé sur un strand, l'exécuteur du canal.
class Channel : public std::enable_shared_from_this<Channel> {
public:
    using ClosedCallback = std::function<void(Channel&)>;

    Channel(std::uint64_t id, asio::any_io_executor strand, ChannelSettings settings, Stats& stats,
            ClosedCallback on_closed);

    // Client : relaie la connexion de l'application (socket sur le strand du canal).
    void start_client(asio::ip::tcp::socket application);
    // Serveur : OPEN reçu sur transport (déjà authentifié) ; se connecte à la destination.
    void start_server(std::shared_ptr<Transport> transport, const tunnel::SessionId& session, PeerIdentity peer);

    // Serveur : RESUME reçu sur une nouvelle connexion de transport. À exécuter
    // sur le strand du canal. En cas de succès, le canal prend la connexion et
    // y répond RESUMED ; sinon l'appelant répond RESUME_FAIL.
    asio::awaitable<bool> accept_resume(std::shared_ptr<Transport> transport, tunnel::Resume request,
                                        PeerIdentity peer, PortKind port);

    // Ferme le canal (en prévenant l'autre tlsrelay). Utilisable depuis n'importe quel thread.
    void abort(CloseReason reason);

    // Vérifie de nouveau le pair après un changement de la liste blanche ; le
    // canal est fermé s'il n'est plus autorisé. Utilisable depuis n'importe quel thread.
    void revalidate();

    // Ferme le canal si sa connexion de transport utilise un autre contexte que
    // ceux donnés (génération retirée). Utilisable depuis n'importe quel thread.
    void close_if_retired(std::shared_ptr<const tls::Context> tls, std::shared_ptr<const tls::Context> mtls);

    // À exécuter sur le strand du canal.
    asio::awaitable<ChannelInfo> describe() const;

    std::uint64_t id() const { return id_; }
    const asio::any_io_executor& executor() const { return executor_; }
    const tunnel::SessionId& session() const { return session_; }

private:
    using Clock = std::chrono::steady_clock;

    // Signal à un seul attendant, mémorisé s'il n'y a personne pour l'attendre.
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
        std::string frame;  // trame DATA encodée
        std::size_t size;   // données utiles
    };

    void spawn(asio::awaitable<void> task);
    asio::awaitable<void> run_client();
    asio::awaitable<void> run_server();
    // Client : nouvelle connexion de transport (TCP, puis TLS avec la génération courante).
    asio::awaitable<std::shared_ptr<Transport>> connect_transport(std::string& failure, CloseReason& reason);

    asio::awaitable<void> sender();
    asio::awaitable<void> uplink();
    asio::awaitable<void> downlink();
    asio::awaitable<void> ack_loop();
    asio::awaitable<void> watchdog();
    asio::awaitable<void> lifetime();
    asio::awaitable<void> keepalive();
    asio::awaitable<void> migrate();
    asio::awaitable<void> goodbye(std::shared_ptr<Transport> transport, std::string frame);
    asio::awaitable<void> retire(std::shared_ptr<Transport> transport);

    // Traite une trame reçue ; faux si le canal doit s'arrêter.
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
    // Ferme le canal. last_frame : trame d'adieu ; par défaut, CLOSE avec le code de la raison.
    void stop(CloseReason reason, std::optional<std::string> last_frame = std::nullopt);
    void finish();

    const std::uint64_t id_;
    asio::any_io_executor executor_;
    ChannelSettings settings_;
    Stats& stats_;
    ClosedCallback on_closed_;
    const Side side_;

    std::shared_ptr<Stream> raw_;  // client : application ; serveur : destination
    std::string raw_peer_;
    tunnel::SessionId session_{};
    PeerIdentity peer_;  // serveur

    // Connexion de transport courante (n = transport_index_) et jeton de reprise.
    std::shared_ptr<Transport> transport_;
    std::uint32_t transport_index_ = 0;
    std::optional<tunnel::Token> token_;
    Clock::time_point transport_since_;
    Duration transport_lifetime_{};          // client : échéance tirée pour la connexion courante
    std::optional<Clock::time_point> broken_since_;  // transport perdu, reprise attendue
    std::shared_ptr<Stream> pending_stream_;  // client : connexion en cours d'ouverture
    bool migrating_ = false;
    bool opened_ = false;  // OPEN_OK envoyé (serveur) ou reçu (client)

    // Émission : trames de contrôle, puis DATA non acquittées (renvoyées après une reprise).
    std::deque<std::string> control_;
    std::deque<Pending> unacked_;
    std::uint64_t unacked_bytes_ = 0;
    std::uint64_t next_seq_ = 1;
    std::uint64_t sent_upto_ = 0;  // dernier seq écrit sur la connexion courante
    bool local_shutdown_ = false;  // fin de la source brute : SHUTDOWN_WR(final_seq_)
    std::uint64_t final_seq_ = 0;
    bool shutdown_sent_ = false;   // SHUTDOWN_WR écrit sur la connexion courante

    // Réception.
    std::uint64_t last_rx_ = 0;
    std::uint64_t acked_rx_ = 0;
    std::uint64_t rx_since_ack_ = 0;  // octets reçus depuis le dernier ACK
    std::optional<std::uint64_t> peer_final_;
    bool raw_shutdown_ = false;

    Event send_event_;
    Event space_event_;
    Event transport_event_;
    Event ack_event_;
    asio::steady_timer idle_timer_;
    asio::steady_timer ack_timer_;
    asio::steady_timer lifetime_timer_;
    asio::steady_timer retry_timer_;
    asio::steady_timer keepalive_timer_;
    Clock::time_point last_frame_;  // dernière trame reçue sur la connexion courante
    std::uint64_t ping_nonce_ = 0;
    bool delivering_ = false;  // écriture vers la connexion brute en cours (contre-pression de l'application)
    asio::cancellation_signal dial_cancel_;

    Clock::time_point opened_at_;
    Clock::time_point last_activity_;
    bool closing_ = false;
    bool finished_ = false;
    int tasks_ = 0;
    std::optional<CloseReason> reason_;
    std::uint64_t raw_in_ = 0;   // octets lus sur la connexion brute
    std::uint64_t raw_out_ = 0;  // octets écrits sur la connexion brute
};

}  // namespace tlsrelay::relay
