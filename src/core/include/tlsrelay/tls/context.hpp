#pragma once

#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/pki/revocation.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <string_view>

// Contexte TLS d'une génération PKI (SPEC §3) : un SSL_CTX par génération.
namespace tlsrelay::tls {

inline constexpr std::string_view kAlpn = "tlsrelay/1";
inline constexpr const char* kCipherSuites =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
inline constexpr const char* kGroups = "X25519:P-256:P-384";

// Listes de révocation en vigueur (SPEC §7.7), partagées par les contextes et
// remplacées à chaud. Absentes : aucune révocation contrôlée.
class Revocations {
public:
    std::shared_ptr<const pki::RevocationList> get() const {
        std::lock_guard lock(mutex_);
        return list_;
    }
    void set(std::shared_ptr<const pki::RevocationList> list) {
        std::lock_guard lock(mutex_);
        list_ = std::move(list);
    }

private:
    mutable std::mutex mutex_;
    std::shared_ptr<const pki::RevocationList> list_;
};

class Context {
public:
    // Lèvent std::runtime_error si la génération ne convient pas ou si OpenSSL
    // refuse la configuration.
    // Serveur : présente l'identité de la génération. En mTLS
    // (require_client_certificate), exige un certificat client émis par l'AC
    // attendue (AC Clients).
    // revocations : certificats du pair refusés s'ils y figurent (facultatif).
    static std::shared_ptr<const Context> make_server(std::shared_ptr<const pki::Generation> generation,
                                                      bool require_client_certificate = false,
                                                      std::shared_ptr<const Revocations> revocations = nullptr);
    // Client : vérifie le serveur (racines et AC Serveurs). En mTLS
    // (present_certificate), présente aussi l'identité de la génération.
    static std::shared_ptr<const Context> make_client(std::shared_ptr<const pki::Generation> generation,
                                                      bool present_certificate = false,
                                                      std::shared_ptr<const Revocations> revocations = nullptr);

    SSL_CTX* native() const { return ctx_.get(); }
    bool is_server() const { return server_; }
    bool verifies_peer() const { return verifies_peer_; }
    const pki::Generation& generation() const { return *generation_; }
    // Vrai si le certificat figure dans les listes de révocation en vigueur.
    bool is_revoked(const X509* cert) const;

    // Crée l'objet SSL d'une connexion. Côté client, server_name sert au SNI
    // et à la vérification du nom (ou de l'adresse IP) du certificat.
    SslPtr new_session(const std::string& server_name) const;

    // Contrôles après handshake : protocole ALPN tlsrelay/1, et si le pair
    // est vérifié, certificat émis par l'AC attendue (déjà contrôlé pendant le
    // handshake ; contrôle redondant par sécurité). Retourne un message
    // d'erreur, vide si tout est conforme.
    std::string check_peer(SSL* ssl) const;

    // Le contexte doit rester à cette adresse : SSL_CTX y fait référence.
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

private:
    Context(SslCtxPtr ctx, std::shared_ptr<const pki::Generation> generation, bool server, bool verify,
            std::shared_ptr<const Revocations> revocations);

    SslCtxPtr ctx_;
    std::shared_ptr<const pki::Generation> generation_;
    std::shared_ptr<const Revocations> revocations_;
    bool server_;
    bool verifies_peer_;  // le certificat du pair est exigé et vérifié
};

// Associe à une session l'emplacement où écrire le motif détaillé d'un refus
// survenu pendant le handshake (par exemple, AC émettrice inattendue).
void set_failure_sink(SSL* ssl, std::string* sink);

}  // namespace tlsrelay::tls
