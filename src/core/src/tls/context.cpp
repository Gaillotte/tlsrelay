#include "tlsrelay/tls/context.hpp"

#include "tlsrelay/endpoint.hpp"

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <stdexcept>

namespace tlsrelay::tls {
namespace {

// ALPN list in wire format: one length byte, then the name.
const std::string& alpn_wire() {
    static const std::string wire = std::string(1, static_cast<char>(kAlpn.size())) + std::string(kAlpn);
    return wire;
}

[[noreturn]] void fail(const std::string& what) {
    throw std::runtime_error(what + ": " + take_openssl_errors());
}

SslCtxPtr make_base(const SSL_METHOD* method) {
    SslCtxPtr ctx(SSL_CTX_new(method));
    if (!ctx) fail("creating the TLS context");
    // TLS 1.3 only.
    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
        fail("restricting to TLS 1.3");
    }
    if (SSL_CTX_set_ciphersuites(ctx.get(), kCipherSuites) != 1) fail("cipher suites");
    if (SSL_CTX_set1_groups_list(ctx.get(), kGroups) != 1) fail("key exchange groups");
    // No session resumption: each connection performs a full handshake (SPEC §3).
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);
    return ctx;
}

int select_alpn(SSL*, const unsigned char** out, unsigned char* out_len, const unsigned char* in, unsigned int in_len,
                void*) {
    const auto& wire = alpn_wire();
    unsigned char* selected = nullptr;
    if (SSL_select_next_proto(&selected, out_len, reinterpret_cast<const unsigned char*>(wire.data()),
                              static_cast<unsigned int>(wire.size()), in, in_len) == OPENSSL_NPN_NEGOTIATED) {
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;  // no_application_protocol alert
}

int failure_index() {
    static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

void report(SSL* ssl, std::string message) {
    if (auto* sink = static_cast<std::string*>(SSL_get_ex_data(ssl, failure_index()))) *sink = std::move(message);
}

const char* peer_role(const Context& context) { return context.is_server() ? "client" : "server"; }

// Called by OpenSSL for each certificate of the peer's chain. At the last one
// (depth 0), the chain is complete: the peer's certificate must have been
// issued by the expected CA (Servers CA on the client side, Clients CA on the
// server side in mTLS). The refusal happens during the handshake: the peer
// receives an alert, and on the server side the destination is never contacted.
int verify_expected_issuer(int preverify_ok, X509_STORE_CTX* store) {
    if (preverify_ok != 1) return 0;
    if (X509_STORE_CTX_get_error_depth(store) != 0) return 1;

    auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
    const auto* context = static_cast<const Context*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
    STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(store);
    const X509* issuer = chain && sk_X509_num(chain) >= 2 ? sk_X509_value(chain, 1) : nullptr;
    if (!context->generation().is_expected_issuer(issuer)) {
        report(ssl, std::string(peer_role(*context)) + " certificate issued by an unexpected CA: " +
                        subject_of(issuer));
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    X509* cert = X509_STORE_CTX_get_current_cert(store);
    if (context->is_revoked(cert)) {
        report(ssl, std::string(peer_role(*context)) + " certificate revoked: " + subject_of(cert));
        X509_STORE_CTX_set_error(store, X509_V_ERR_CERT_REVOKED);
        return 0;
    }
    return 1;
}

void use_identity(SSL_CTX* ctx, const pki::Generation& generation) {
    if (SSL_CTX_use_certificate(ctx, generation.cert.get()) != 1) fail("certificate");
    for (const auto& ca : generation.chain) {
        if (SSL_CTX_add1_chain_cert(ctx, ca.get()) != 1) fail("certificate chain");
    }
    if (SSL_CTX_use_PrivateKey(ctx, generation.key.get()) != 1) fail("private key");
    if (SSL_CTX_check_private_key(ctx) != 1) fail("key / certificate consistency");
}

void verify_peer(SSL_CTX* ctx, const pki::Generation& generation, int mode, int purpose) {
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    for (const auto& root : generation.trust_roots) {
        if (X509_STORE_add_cert(store, root.get()) != 1) fail("trusted root");
    }
    SSL_CTX_set_verify(ctx, mode, verify_expected_issuer);
    if (SSL_CTX_set_purpose(ctx, purpose) != 1) fail("expected purpose of the peer certificate");
}

bool has_identity(const pki::Generation* g) { return g && g->cert && g->key; }
bool has_trust(const pki::Generation* g) { return g && !g->trust_roots.empty() && !g->trust_issuers.empty(); }

}  // namespace

void set_failure_sink(SSL* ssl, std::string* sink) { SSL_set_ex_data(ssl, failure_index(), sink); }

Context::Context(SslCtxPtr ctx, std::shared_ptr<const pki::Generation> generation, bool server, bool verify,
                 std::shared_ptr<const Revocations> revocations)
    : ctx_(std::move(ctx)),
      generation_(std::move(generation)),
      revocations_(std::move(revocations)),
      server_(server),
      verifies_peer_(verify) {}

bool Context::is_revoked(const X509* cert) const {
    if (!revocations_) return false;
    const auto list = revocations_->get();
    return list && list->is_revoked(cert);
}

std::shared_ptr<const Context> Context::make_server(std::shared_ptr<const pki::Generation> generation,
                                                    bool require_client_certificate,
                                                    std::shared_ptr<const Revocations> revocations) {
    if (!has_identity(generation.get())) {
        throw std::runtime_error("server TLS context: identity missing from the generation");
    }
    if (require_client_certificate && !has_trust(generation.get())) {
        throw std::runtime_error("server mTLS context: roots or Clients CA missing from the generation");
    }
    auto ctx = make_base(TLS_server_method());
    SSL_CTX_set_num_tickets(ctx.get(), 0);
    use_identity(ctx.get(), *generation);
    if (require_client_certificate) {
        verify_peer(ctx.get(), *generation, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, X509_PURPOSE_SSL_CLIENT);
    }
    SSL_CTX_set_alpn_select_cb(ctx.get(), select_alpn, nullptr);
    auto context = std::shared_ptr<Context>(
        new Context(std::move(ctx), std::move(generation), true, require_client_certificate, std::move(revocations)));
    SSL_CTX_set_app_data(context->ctx_.get(), context.get());  // read by verify_expected_issuer
    return context;
}

std::shared_ptr<const Context> Context::make_client(std::shared_ptr<const pki::Generation> generation,
                                                    bool present_certificate,
                                                    std::shared_ptr<const Revocations> revocations) {
    if (!has_trust(generation.get())) {
        throw std::runtime_error("client TLS context: roots or expected CA missing from the generation");
    }
    if (present_certificate && !has_identity(generation.get())) {
        throw std::runtime_error("client mTLS context: identity missing from the generation");
    }
    auto ctx = make_base(TLS_client_method());
    verify_peer(ctx.get(), *generation, SSL_VERIFY_PEER, X509_PURPOSE_SSL_SERVER);
    if (present_certificate) use_identity(ctx.get(), *generation);
    const auto& wire = alpn_wire();
    // Beware: SSL_CTX_set_alpn_protos returns 0 on success.
    if (SSL_CTX_set_alpn_protos(ctx.get(), reinterpret_cast<const unsigned char*>(wire.data()),
                                static_cast<unsigned int>(wire.size())) != 0) {
        fail("ALPN protocol");
    }
    auto context = std::shared_ptr<Context>(
        new Context(std::move(ctx), std::move(generation), false, true, std::move(revocations)));
    SSL_CTX_set_app_data(context->ctx_.get(), context.get());  // read by verify_expected_issuer
    return context;
}

SslPtr Context::new_session(const std::string& server_name) const {
    SslPtr ssl(SSL_new(ctx_.get()));
    if (!ssl) fail("creating the TLS session");
    if (server_) return ssl;

    X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (is_ip_literal(server_name)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, server_name.c_str()) != 1) fail("server IP address");
    } else {
        if (SSL_set1_host(ssl.get(), server_name.c_str()) != 1) fail("server name");
        if (SSL_set_tlsext_host_name(ssl.get(), server_name.c_str()) != 1) fail("SNI");
    }
    return ssl;
}

std::string Context::check_peer(SSL* ssl) const {
    const unsigned char* proto = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(ssl, &proto, &length);
    if (std::string_view(reinterpret_cast<const char*>(proto), proto ? length : 0) != kAlpn) {
        return "application protocol tlsrelay/1 not negotiated (ALPN)";
    }
    if (verifies_peer_) {
        // Redundant check of verify_expected_issuer: certificate present,
        // chain verified, issued by the expected CA.
        const std::string role = server_ ? "client" : "server";
        if (!SSL_get0_peer_certificate(ssl) || SSL_get_verify_result(ssl) != X509_V_OK) {
            return role + " certificate missing or not verified";
        }
        STACK_OF(X509)* chain = SSL_get0_verified_chain(ssl);
        if (!chain || sk_X509_num(chain) < 2) return role + " chain incomplete";
        if (!generation_->is_expected_issuer(sk_X509_value(chain, 1))) {
            return role + " certificate issued by an unexpected CA: " + subject_of(sk_X509_value(chain, 1));
        }
        if (is_revoked(SSL_get0_peer_certificate(ssl))) return role + " certificate revoked";
    }
    return {};
}

}  // namespace tlsrelay::tls
