#include "tlsrelay/tls/context.hpp"

#include "tlsrelay/endpoint.hpp"

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <stdexcept>

namespace tlsrelay::tls {
namespace {

// Liste ALPN au format du protocole : longueur sur un octet puis le nom.
const std::string& alpn_wire() {
    static const std::string wire = std::string(1, static_cast<char>(kAlpn.size())) + std::string(kAlpn);
    return wire;
}

[[noreturn]] void fail(const std::string& what) {
    throw std::runtime_error(what + " : " + take_openssl_errors());
}

SslCtxPtr make_base(const SSL_METHOD* method) {
    SslCtxPtr ctx(SSL_CTX_new(method));
    if (!ctx) fail("création du contexte TLS");
    // TLS 1.3 uniquement.
    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
        fail("restriction à TLS 1.3");
    }
    if (SSL_CTX_set_ciphersuites(ctx.get(), kCipherSuites) != 1) fail("suites de chiffrement");
    if (SSL_CTX_set1_groups_list(ctx.get(), kGroups) != 1) fail("groupes d'échange de clés");
    // Pas de reprise de session : chaque connexion fait un handshake complet (SPEC §3).
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
    return SSL_TLSEXT_ERR_ALERT_FATAL;  // alerte no_application_protocol
}

int failure_index() {
    static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

void report(SSL* ssl, std::string message) {
    if (auto* sink = static_cast<std::string*>(SSL_get_ex_data(ssl, failure_index()))) *sink = std::move(message);
}

const char* peer_role(const Context& context) { return context.is_server() ? "client" : "serveur"; }

// Appelé par OpenSSL pour chaque certificat de la chaîne du pair. Au dernier
// (profondeur 0), la chaîne est complète : le certificat du pair doit avoir
// été émis par l'AC attendue (AC Serveurs côté client, AC Clients côté
// serveur en mTLS). Le refus intervient pendant le handshake : le pair reçoit
// une alerte, et côté serveur la destination n'est jamais contactée.
int verify_expected_issuer(int preverify_ok, X509_STORE_CTX* store) {
    if (preverify_ok != 1) return 0;
    if (X509_STORE_CTX_get_error_depth(store) != 0) return 1;

    auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
    const auto* context = static_cast<const Context*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
    STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(store);
    const X509* issuer = chain && sk_X509_num(chain) >= 2 ? sk_X509_value(chain, 1) : nullptr;
    if (!issuer || X509_cmp(issuer, context->generation().trust_issuer.get()) != 0) {
        report(ssl, std::string("certificat du ") + peer_role(*context) + " émis par une AC inattendue : " +
                        subject_of(issuer));
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    return 1;
}

void use_identity(SSL_CTX* ctx, const pki::Generation& generation) {
    if (SSL_CTX_use_certificate(ctx, generation.cert.get()) != 1) fail("certificat");
    for (const auto& ca : generation.chain) {
        if (SSL_CTX_add1_chain_cert(ctx, ca.get()) != 1) fail("chaîne de certification");
    }
    if (SSL_CTX_use_PrivateKey(ctx, generation.key.get()) != 1) fail("clé privée");
    if (SSL_CTX_check_private_key(ctx) != 1) fail("cohérence clé / certificat");
}

void verify_peer(SSL_CTX* ctx, const pki::Generation& generation, int mode, int purpose) {
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    for (const auto& root : generation.trust_roots) {
        if (X509_STORE_add_cert(store, root.get()) != 1) fail("racine de confiance");
    }
    SSL_CTX_set_verify(ctx, mode, verify_expected_issuer);
    if (SSL_CTX_set_purpose(ctx, purpose) != 1) fail("usage attendu du certificat du pair");
}

bool has_identity(const pki::Generation* g) { return g && g->cert && g->key; }
bool has_trust(const pki::Generation* g) { return g && !g->trust_roots.empty() && g->trust_issuer; }

}  // namespace

void set_failure_sink(SSL* ssl, std::string* sink) { SSL_set_ex_data(ssl, failure_index(), sink); }

Context::Context(SslCtxPtr ctx, std::shared_ptr<const pki::Generation> generation, bool server, bool verify)
    : ctx_(std::move(ctx)), generation_(std::move(generation)), server_(server), verifies_peer_(verify) {}

std::shared_ptr<const Context> Context::make_server(std::shared_ptr<const pki::Generation> generation,
                                                    bool require_client_certificate) {
    if (!has_identity(generation.get())) {
        throw std::runtime_error("contexte TLS serveur : identité absente de la génération");
    }
    if (require_client_certificate && !has_trust(generation.get())) {
        throw std::runtime_error("contexte mTLS serveur : racines ou AC Clients absentes de la génération");
    }
    auto ctx = make_base(TLS_server_method());
    SSL_CTX_set_num_tickets(ctx.get(), 0);
    use_identity(ctx.get(), *generation);
    if (require_client_certificate) {
        verify_peer(ctx.get(), *generation, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, X509_PURPOSE_SSL_CLIENT);
    }
    SSL_CTX_set_alpn_select_cb(ctx.get(), select_alpn, nullptr);
    auto context = std::shared_ptr<Context>(
        new Context(std::move(ctx), std::move(generation), true, require_client_certificate));
    SSL_CTX_set_app_data(context->ctx_.get(), context.get());  // lu par verify_expected_issuer
    return context;
}

std::shared_ptr<const Context> Context::make_client(std::shared_ptr<const pki::Generation> generation,
                                                    bool present_certificate) {
    if (!has_trust(generation.get())) {
        throw std::runtime_error("contexte TLS client : racines ou AC attendue absentes de la génération");
    }
    if (present_certificate && !has_identity(generation.get())) {
        throw std::runtime_error("contexte mTLS client : identité absente de la génération");
    }
    auto ctx = make_base(TLS_client_method());
    verify_peer(ctx.get(), *generation, SSL_VERIFY_PEER, X509_PURPOSE_SSL_SERVER);
    if (present_certificate) use_identity(ctx.get(), *generation);
    const auto& wire = alpn_wire();
    // Attention : SSL_CTX_set_alpn_protos retourne 0 en cas de succès.
    if (SSL_CTX_set_alpn_protos(ctx.get(), reinterpret_cast<const unsigned char*>(wire.data()),
                                static_cast<unsigned int>(wire.size())) != 0) {
        fail("protocole ALPN");
    }
    auto context = std::shared_ptr<Context>(new Context(std::move(ctx), std::move(generation), false, true));
    SSL_CTX_set_app_data(context->ctx_.get(), context.get());  // lu par verify_expected_issuer
    return context;
}

SslPtr Context::new_session(const std::string& server_name) const {
    SslPtr ssl(SSL_new(ctx_.get()));
    if (!ssl) fail("création de la session TLS");
    if (server_) return ssl;

    X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (is_ip_literal(server_name)) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, server_name.c_str()) != 1) fail("adresse IP du serveur");
    } else {
        if (SSL_set1_host(ssl.get(), server_name.c_str()) != 1) fail("nom du serveur");
        if (SSL_set_tlsext_host_name(ssl.get(), server_name.c_str()) != 1) fail("SNI");
    }
    return ssl;
}

std::string Context::check_peer(SSL* ssl) const {
    const unsigned char* proto = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(ssl, &proto, &length);
    if (std::string_view(reinterpret_cast<const char*>(proto), proto ? length : 0) != kAlpn) {
        return "protocole applicatif tlsrelay/1 non négocié (ALPN)";
    }
    if (verifies_peer_) {
        // Contrôle redondant de verify_expected_issuer : certificat présent,
        // chaîne vérifiée, émis par l'AC attendue.
        const std::string role = server_ ? "client" : "serveur";
        if (!SSL_get0_peer_certificate(ssl) || SSL_get_verify_result(ssl) != X509_V_OK) {
            return "certificat du " + role + " absent ou non vérifié";
        }
        STACK_OF(X509)* chain = SSL_get0_verified_chain(ssl);
        if (!chain || sk_X509_num(chain) < 2) return "chaîne du " + role + " incomplète";
        if (X509_cmp(sk_X509_value(chain, 1), generation_->trust_issuer.get()) != 0) {
            return "certificat du " + role + " émis par une AC inattendue : " + subject_of(sk_X509_value(chain, 1));
        }
    }
    return {};
}

}  // namespace tlsrelay::tls
