#include "tlsrelay/pki/generation.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <fstream>
#include <sstream>

namespace tlsrelay::pki {
namespace {

namespace fs = std::filesystem;
using tls::X509Ptr;

constexpr const char* kKeyFile = "key.pem";
constexpr const char* kCertFile = "cert.pem";
constexpr const char* kChainFile = "chain.pem";
constexpr const char* kRootsFile = "trust-roots.pem";
constexpr const char* kIssuerFile = "trust-issuer.pem";

std::optional<std::string> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream content;
    content << in.rdbuf();
    return content.str();
}

tls::BioPtr memory_bio(const std::string& data) {
    return tls::BioPtr(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
}

// Refuses any passphrase prompt: an encrypted key is an error
// (and OpenSSL must never try to read it from the terminal).
int no_password(char*, int, int, void*) { return 0; }

class Loader {
public:
    Loader(const fs::path& dir, LoadResult& result) : dir_(dir), result_(result) {}

    std::vector<X509Ptr> certificates(const char* file, bool required) {
        std::vector<X509Ptr> certs;
        const auto content = read_file(dir_ / file);
        if (!content) {
            if (required) error(file, "missing or unreadable file");
            return certs;
        }
        auto bio = memory_bio(*content);
        while (X509* cert = PEM_read_bio_X509(bio.get(), nullptr, no_password, nullptr)) certs.emplace_back(cert);
        ERR_clear_error();  // end of file is reported as an error
        if (certs.empty()) error(file, "no PEM certificate found");
        return certs;
    }

    tls::EvpPkeyPtr key(const char* file) {
        const auto content = read_file(dir_ / file);
        if (!content) {
            error(file, "missing or unreadable file");
            return nullptr;
        }
        auto bio = memory_bio(*content);
        tls::EvpPkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, no_password, nullptr));
        if (!key) error(file, "PEM private key unreadable or encrypted: " + tls::take_openssl_errors());
        return key;
    }

    void error(const std::string& file, std::string message) {
        result_.errors.push_back({path(file), std::move(message)});
    }
    void warning(const std::string& file, std::string message) {
        result_.warnings.push_back({path(file), std::move(message)});
    }

private:
    std::string path(const std::string& file) const { return (dir_ / file).string(); }

    fs::path dir_;
    LoadResult& result_;
};

// Checks validity dates; warns if expiry is near.
void check_dates(Loader& loader, const char* file, const X509* cert, Duration warning) {
    const auto who = tls::subject_of(cert);
    if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0) {
        loader.error(file, "certificate not yet valid: " + who);
    }
    if (X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) {
        loader.error(file, "certificate expired on " + tls::not_after_of(cert) + ": " + who);
        return;
    }
    std::time_t limit = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(warning).count();
    if (X509_cmp_time(X509_get0_notAfter(cert), &limit) < 0) {
        loader.warning(file, "certificate expiring on " + tls::not_after_of(cert) + ": " + who);
    }
}

// Verifies cert up to a root of trust_roots, with the requested purpose.
std::optional<std::string> verify(const X509* cert, const std::vector<X509Ptr>& untrusted,
                                  const std::vector<X509Ptr>& roots, int purpose) {
    tls::X509StorePtr store(X509_STORE_new());
    for (const auto& root : roots) X509_STORE_add_cert(store.get(), root.get());

    STACK_OF(X509)* stack = sk_X509_new_null();
    for (const auto& c : untrusted) sk_X509_push(stack, c.get());  // no ownership transfer

    tls::X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    std::optional<std::string> failure;
    if (X509_STORE_CTX_init(ctx.get(), store.get(), const_cast<X509*>(cert), stack) != 1) {
        failure = tls::take_openssl_errors();
    } else {
        if (purpose != 0) X509_STORE_CTX_set_purpose(ctx.get(), purpose);
        if (X509_verify_cert(ctx.get()) != 1) {
            failure = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()));
            ERR_clear_error();
        }
    }
    sk_X509_free(stack);
    return failure;
}

bool valid_generation_name(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    return name.find_first_of("/\\:") == std::string::npos;
}

}  // namespace

LoadResult load_generation(const fs::path& dir, const Requirements& req) {
    LoadResult result;
    Loader loader(dir, result);
    auto gen = std::make_shared<Generation>();
    gen->name = dir.filename().string();
    gen->dir = dir;

    const int purpose = req.role == Role::server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
    const char* role_name = req.role == Role::server ? "server (serverAuth)" : "client (clientAuth)";

    // The trusted roots are read whenever the file is present, even if
    // they are not used to verify a peer: the rotation safeguard uses
    // them to check the new identity (rotation_guard).
    if (!req.trust && fs::exists(dir / kRootsFile)) {
        gen->trust_roots = loader.certificates(kRootsFile, false);
    }
    if (req.trust) {
        gen->trust_roots = loader.certificates(kRootsFile, true);
        for (const auto& root : gen->trust_roots) {
            if (X509_check_ca(root.get()) < 1) loader.error(kRootsFile, "not a CA: " + tls::subject_of(root.get()));
            check_dates(loader, kRootsFile, root.get(), req.expiry_warning);
        }
        // One expected CA per root: several during a root change (SPEC §7.5).
        gen->trust_issuers = loader.certificates(kIssuerFile, true);
        for (const auto& issuer : gen->trust_issuers) {
            const X509* ca = issuer.get();
            if (X509_check_ca(const_cast<X509*>(ca)) < 1) loader.error(kIssuerFile, "not a CA: " + tls::subject_of(ca));
            check_dates(loader, kIssuerFile, ca, req.expiry_warning);
            if (!gen->trust_roots.empty()) {
                if (auto failure = verify(ca, {}, gen->trust_roots, 0)) {
                    loader.error(kIssuerFile, tls::subject_of(ca) + " does not chain to the trusted roots: " +
                                                  *failure);
                }
            }
        }
    }

    if (req.identity) {
        gen->key = loader.key(kKeyFile);
        auto certs = loader.certificates(kCertFile, true);
        if (certs.size() > 1) loader.error(kCertFile, "a single certificate expected (CAs go in chain.pem)");
        if (!certs.empty()) gen->cert = std::move(certs.front());
        gen->chain = loader.certificates(kChainFile, true);

        if (gen->cert) {
            const X509* cert = gen->cert.get();
            check_dates(loader, kCertFile, cert, req.expiry_warning);
            if (gen->key && X509_check_private_key(cert, gen->key.get()) != 1) {
                ERR_clear_error();
                loader.error(kKeyFile, "the key does not match the certificate " + tls::subject_of(cert));
            }
            if (X509_check_purpose(const_cast<X509*>(cert), purpose, 0) != 1) {
                loader.error(kCertFile, std::string("usage incompatible with role ") + role_name);
            }
            if (!gen->chain.empty() && X509_check_issued(gen->chain.front().get(), const_cast<X509*>(cert)) != X509_V_OK) {
                loader.error(kChainFile, "the first certificate is not the issuer of cert.pem");
            }
            for (const auto& ca : gen->chain) check_dates(loader, kChainFile, ca.get(), req.expiry_warning);
            // With roots available, the full chain must verify.
            if (!gen->trust_roots.empty() && !gen->chain.empty()) {
                if (auto failure = verify(cert, gen->chain, gen->trust_roots, purpose)) {
                    loader.error(kCertFile, "invalid chain: " + *failure);
                }
            }
        }
    }

    if (result.errors.empty()) result.generation = std::move(gen);
    return result;
}

bool Generation::is_expected_issuer(const X509* ca) const {
    if (!ca) return false;
    for (const auto& issuer : trust_issuers) {
        if (X509_cmp(ca, issuer.get()) == 0) return true;
    }
    return false;
}

bool Generation::shares_root_with(const Generation& other) const {
    for (const auto& a : trust_roots) {
        for (const auto& b : other.trust_roots) {
            if (X509_cmp(a.get(), b.get()) == 0) return true;
        }
    }
    return false;
}

LoadResult load_current_generation(const fs::path& pki_root, const Requirements& req) {
    const auto pointer = pki_root / "current";
    auto content = read_file(pointer);
    if (!content) {
        LoadResult result;
        result.errors.push_back({pointer.string(), "missing or unreadable file"});
        return result;
    }
    while (!content->empty() && (content->back() == '\n' || content->back() == '\r' || content->back() == ' ')) {
        content->pop_back();
    }
    if (!valid_generation_name(*content)) {
        LoadResult result;
        result.errors.push_back({pointer.string(), "invalid generation name \"" + *content + "\""});
        return result;
    }
    return load_generation(pki_root / *content, req);
}

std::optional<std::string> rotation_guard(const Generation& current, const Generation& next, const Requirements& req) {
    if (current.name == next.name) return std::nullopt;
    // Roots: at least one in common, otherwise peers still on the old
    // generation would be refused (step 1 of the root change missing).
    if (req.trust && !next.shares_root_with(current)) {
        return "no trusted root in common with generation " + current.name +
               "; to change the root, first add the new root (SPEC §7.5)";
    }
    // Identity: the new certificate must chain to a root already known
    // to the current generation, otherwise peers that do not yet know
    // its root could no longer connect.
    if (next.cert) {
        const int purpose = req.role == Role::server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
        if (!current.trust_roots.empty()) {
            if (auto failure = verify(next.cert.get(), next.chain, current.trust_roots, purpose)) {
                return "the new certificate does not chain to any trusted root of generation " +
                       current.name + " (" + *failure + "); to change the root, first add the new "
                       "root (SPEC §7.5)";
            }
        } else if (!current.chain.empty() && !next.chain.empty() &&
                   X509_NAME_cmp(X509_get_issuer_name(current.chain.back().get()),
                                 X509_get_issuer_name(next.chain.back().get())) != 0) {
            return "the new certificate depends on a different root than generation " + current.name +
                   "; add trust-roots.pem (roots known to the peers) to allow a root change";
        }
    }
    return std::nullopt;
}

LoadResult check_candidate(const fs::path& pki_root, const std::string& name, const Requirements& req) {
    if (!valid_generation_name(name)) {
        LoadResult result;
        result.errors.push_back({name, "invalid generation name"});
        return result;
    }
    auto result = load_generation(pki_root / name, req);
    if (!result.generation) return result;

    const auto current = load_current_generation(pki_root, req);
    if (!current.generation) {
        std::error_code ec;
        if (!fs::exists(pki_root / "current", ec)) return result;  // first activation: nothing to preserve
        result.warnings.push_back({(pki_root / "current").string(),
                                   "current generation unreadable: root safeguard not checked"});
    } else if (auto problem = rotation_guard(*current.generation, *result.generation, req)) {
        result.errors.push_back({(pki_root / name).string(), "rotation safeguard: " + *problem});
        result.generation.reset();
    }
    return result;
}

void activate(const fs::path& pki_root, const std::string& name) {
    if (!valid_generation_name(name)) {
        throw fs::filesystem_error("invalid generation name", pki_root / name,
                                   std::make_error_code(std::errc::invalid_argument));
    }
    const auto tmp = pki_root / "current.tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out << name << "\n";
        if (!out) throw fs::filesystem_error("cannot write", tmp, std::make_error_code(std::errc::io_error));
    }
    fs::rename(tmp, pki_root / "current");  // atomic replacement
}

std::optional<Requirements> requirements_for(const Config& config) {
    const bool tls = config.ports.count(PortKind::tls) != 0;
    const bool mtls = config.ports.count(PortKind::mtls) != 0;
    if (!tls && !mtls) return std::nullopt;

    Requirements req;
    if (config.credentials) req.expiry_warning = config.credentials->expiry_warning;
    if (config.mode == Mode::server) {
        req.role = Role::server;
        req.identity = true;  // the server always presents its certificate
        req.trust = mtls;     // it verifies clients in mTLS
    } else {
        req.role = Role::client;
        req.trust = true;     // the client always verifies the server
        req.identity = mtls;  // it presents its certificate in mTLS
    }
    return req;
}

}  // namespace tlsrelay::pki
