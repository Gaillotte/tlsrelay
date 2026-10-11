#pragma once

#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"

#include <memory>
#include <string>
#include <string_view>

// Contexte TLS d'une génération PKI (SPEC §3) : un SSL_CTX par génération.
namespace tlsrelay::tls {

inline constexpr std::string_view kAlpn = "tlsrelay/1";
inline constexpr const char* kCipherSuites =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
inline constexpr const char* kGroups = "X25519:P-256:P-384";

class Context {
public:
    // Lèvent std::runtime_error si OpenSSL refuse la configuration.
    // Serveur : présente l'identité de la génération (exige identity).
    static std::shared_ptr<const Context> make_server(std::shared_ptr<const pki::Generation> generation);
    // Client : vérifie le serveur avec les racines et l'AC attendue (exige trust).
    static std::shared_ptr<const Context> make_client(std::shared_ptr<const pki::Generation> generation);

    SSL_CTX* native() const { return ctx_.get(); }
    bool is_server() const { return server_; }
    const pki::Generation& generation() const { return *generation_; }

    // Crée l'objet SSL d'une connexion. Côté client, server_name sert au SNI
    // et à la vérification du nom (ou de l'adresse IP) du certificat.
    SslPtr new_session(const std::string& server_name) const;

    // Contrôles après handshake : protocole ALPN tlsrelay/1, et côté client,
    // certificat du serveur émis par l'AC attendue (déjà vérifié pendant le
    // handshake ; contrôle redondant par sécurité). Retourne un message
    // d'erreur, vide si tout est conforme.
    std::string check_peer(SSL* ssl) const;

    // Le contexte doit rester à cette adresse : SSL_CTX y fait référence.
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

private:
    Context(SslCtxPtr ctx, std::shared_ptr<const pki::Generation> generation, bool server);

    SslCtxPtr ctx_;
    std::shared_ptr<const pki::Generation> generation_;
    bool server_;
};

// Associe à une session l'emplacement où écrire le motif détaillé d'un refus
// survenu pendant le handshake (par exemple, AC émettrice inattendue).
void set_failure_sink(SSL* ssl, std::string* sink);

}  // namespace tlsrelay::tls
