#pragma once

#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/pki/revocation.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <string_view>

// TLS context of a PKI generation (SPEC §3): one SSL_CTX per generation.
namespace tlsrelay::tls {

inline constexpr std::string_view kAlpn = "tlsrelay/1";
inline constexpr const char* kCipherSuites =
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
inline constexpr const char* kGroups = "X25519:P-256:P-384";

// Revocation lists in force (SPEC §7.7), shared by the contexts and
// replaced on the fly. Absent: no revocation checked.
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
    // Throw std::runtime_error if the generation is unsuitable or if OpenSSL
    // refuses the configuration.
    // Server: presents the generation's identity. In mTLS
    // (require_client_certificate), requires a client certificate issued by the
    // expected CA (Clients CA).
    // revocations: peer certificates listed there are refused (optional).
    static std::shared_ptr<const Context> make_server(std::shared_ptr<const pki::Generation> generation,
                                                      bool require_client_certificate = false,
                                                      std::shared_ptr<const Revocations> revocations = nullptr);
    // Client: verifies the server (roots and Servers CA). In mTLS
    // (present_certificate), also presents the generation's identity.
    static std::shared_ptr<const Context> make_client(std::shared_ptr<const pki::Generation> generation,
                                                      bool present_certificate = false,
                                                      std::shared_ptr<const Revocations> revocations = nullptr);

    SSL_CTX* native() const { return ctx_.get(); }
    bool is_server() const { return server_; }
    bool verifies_peer() const { return verifies_peer_; }
    const pki::Generation& generation() const { return *generation_; }
    // True if the certificate appears in the revocation lists in force.
    bool is_revoked(const X509* cert) const;

    // Creates the SSL object of a connection. On the client side, server_name is
    // used for SNI and to verify the certificate's name (or IP address).
    SslPtr new_session(const std::string& server_name) const;

    // Checks after the handshake: ALPN protocol tlsrelay/1, and if the peer
    // is verified, certificate issued by the expected CA (already checked during
    // the handshake; redundant check for safety). Returns an error message,
    // empty if everything conforms.
    std::string check_peer(SSL* ssl) const;

    // The context must stay at this address: SSL_CTX refers to it.
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

private:
    Context(SslCtxPtr ctx, std::shared_ptr<const pki::Generation> generation, bool server, bool verify,
            std::shared_ptr<const Revocations> revocations);

    SslCtxPtr ctx_;
    std::shared_ptr<const pki::Generation> generation_;
    std::shared_ptr<const Revocations> revocations_;
    bool server_;
    bool verifies_peer_;  // the peer certificate is required and verified
};

// Associates with a session the location where the detailed reason of a refusal
// during the handshake is written (for example, unexpected issuing CA).
void set_failure_sink(SSL* ssl, std::string* sink);

}  // namespace tlsrelay::tls
