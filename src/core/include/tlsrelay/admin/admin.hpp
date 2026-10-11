#pragma once

// Canal d'administration (SPEC §10) : une commande par connexion.
//
//   requête : une ligne de texte « commande arg1 arg2 ...\n » (4 Kio au plus)
//   réponse : « OK <n>\n » ou « ERREUR <n>\n », puis n octets de texte UTF-8
//
// Linux : socket Unix (par défaut /run/tlsrelay/<instance>.sock, droits 0660,
// groupe tlsrelay s'il existe). Windows : named pipe \\.\pipe\tlsrelay-<instance>,
// accessible aux Administrateurs, à SYSTEM et au compte qui exécute l'instance,
// refusé aux clients distants. Le canal sert aussi de verrou d'instance : une
// seule exécution par instance.

#include "tlsrelay/config.hpp"
#include "tlsrelay/units.hpp"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace tlsrelay::admin {

inline constexpr std::size_t kMaxRequest = 4096;

// Point d'accès par défaut d'une instance.
std::string default_endpoint(const std::string& instance);
// Point d'accès d'une configuration (admin.endpoint, sinon le défaut).
std::string endpoint_for(const Config& config);

struct Request {
    std::string command;
    std::vector<std::string> args;
};

// Découpe une ligne en mots séparés par des espaces. std::nullopt si la ligne
// est vide ou contient des caractères de contrôle.
std::optional<Request> parse_request(std::string_view line);

struct Reply {
    bool ok = true;
    std::string body;
};

std::string encode_reply(const Reply& reply);

// Résultat d'un appel client : reply absent si l'instance est injoignable
// (error donne la raison).
struct CallResult {
    std::optional<Reply> reply;
    std::string error;
    bool unreachable = false;  // aucune instance n'écoute sur ce point d'accès
};

// Client bloquant (ligne de commande).
CallResult call(const std::string& endpoint, const std::string& request, Duration timeout);

// Traite les commandes reçues. caller décrit l'appelant (uid ou pid) pour le journal.
class Handler {
public:
    virtual ~Handler() = default;
    virtual asio::awaitable<Reply> handle(Request request, std::string caller) = 0;
};

// Une autre exécution de la même instance tient déjà le canal.
class AlreadyRunning : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Serveur du canal. Le constructeur prend le verrou d'instance et ouvre le
// point d'accès ; il lève std::runtime_error si une autre exécution de la même
// instance est en cours ou si le point d'accès ne peut pas être créé.
class Server {
public:
    Server(asio::io_context& io, std::string endpoint, Handler& handler);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void start();
    // Ferme le point d'accès (les commandes en cours se terminent). Utilisable depuis n'importe quel thread.
    void stop();

    const std::string& endpoint() const;

    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

}  // namespace tlsrelay::admin
