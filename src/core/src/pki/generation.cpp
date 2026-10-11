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

// Refuse toute demande de phrase de passe : une clé chiffrée est une erreur
// (et OpenSSL ne doit jamais tenter de la lire sur le terminal).
int no_password(char*, int, int, void*) { return 0; }

class Loader {
public:
    Loader(const fs::path& dir, LoadResult& result) : dir_(dir), result_(result) {}

    std::vector<X509Ptr> certificates(const char* file, bool required) {
        std::vector<X509Ptr> certs;
        const auto content = read_file(dir_ / file);
        if (!content) {
            if (required) error(file, "fichier absent ou illisible");
            return certs;
        }
        auto bio = memory_bio(*content);
        while (X509* cert = PEM_read_bio_X509(bio.get(), nullptr, no_password, nullptr)) certs.emplace_back(cert);
        ERR_clear_error();  // la fin de fichier est signalée comme une erreur
        if (certs.empty()) error(file, "aucun certificat PEM trouvé");
        return certs;
    }

    tls::EvpPkeyPtr key(const char* file) {
        const auto content = read_file(dir_ / file);
        if (!content) {
            error(file, "fichier absent ou illisible");
            return nullptr;
        }
        auto bio = memory_bio(*content);
        tls::EvpPkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, no_password, nullptr));
        if (!key) error(file, "clé privée PEM illisible ou chiffrée : " + tls::take_openssl_errors());
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

// Contrôle des dates de validité ; avertit si l'échéance est proche.
void check_dates(Loader& loader, const char* file, const X509* cert, Duration warning) {
    const auto who = tls::subject_of(cert);
    if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0) {
        loader.error(file, "certificat pas encore valide : " + who);
    }
    if (X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) {
        loader.error(file, "certificat expiré le " + tls::not_after_of(cert) + " : " + who);
        return;
    }
    std::time_t limit = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(warning).count();
    if (X509_cmp_time(X509_get0_notAfter(cert), &limit) < 0) {
        loader.warning(file, "certificat expirant le " + tls::not_after_of(cert) + " : " + who);
    }
}

// Vérifie cert jusqu'à une racine de trust_roots, avec l'usage demandé.
std::optional<std::string> verify(const X509* cert, const std::vector<X509Ptr>& untrusted,
                                  const std::vector<X509Ptr>& roots, int purpose) {
    tls::X509StorePtr store(X509_STORE_new());
    for (const auto& root : roots) X509_STORE_add_cert(store.get(), root.get());

    STACK_OF(X509)* stack = sk_X509_new_null();
    for (const auto& c : untrusted) sk_X509_push(stack, c.get());  // sans transfert de propriété

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
    const char* role_name = req.role == Role::server ? "serveur (serverAuth)" : "client (clientAuth)";

    if (req.trust) {
        gen->trust_roots = loader.certificates(kRootsFile, true);
        for (const auto& root : gen->trust_roots) {
            if (X509_check_ca(root.get()) < 1) loader.error(kRootsFile, "n'est pas une AC : " + tls::subject_of(root.get()));
            check_dates(loader, kRootsFile, root.get(), req.expiry_warning);
        }
        auto issuer = loader.certificates(kIssuerFile, true);
        if (issuer.size() > 1) loader.error(kIssuerFile, "un seul certificat attendu");
        if (!issuer.empty()) {
            gen->trust_issuer = std::move(issuer.front());
            const X509* ca = gen->trust_issuer.get();
            if (X509_check_ca(const_cast<X509*>(ca)) < 1) loader.error(kIssuerFile, "n'est pas une AC : " + tls::subject_of(ca));
            check_dates(loader, kIssuerFile, ca, req.expiry_warning);
            if (!gen->trust_roots.empty()) {
                if (auto failure = verify(ca, {}, gen->trust_roots, 0)) {
                    loader.error(kIssuerFile, "ne se rattache pas aux racines de confiance : " + *failure);
                }
            }
        }
    }

    if (req.identity) {
        gen->key = loader.key(kKeyFile);
        auto certs = loader.certificates(kCertFile, true);
        if (certs.size() > 1) loader.error(kCertFile, "un seul certificat attendu (les AC vont dans chain.pem)");
        if (!certs.empty()) gen->cert = std::move(certs.front());
        gen->chain = loader.certificates(kChainFile, true);

        if (gen->cert) {
            const X509* cert = gen->cert.get();
            check_dates(loader, kCertFile, cert, req.expiry_warning);
            if (gen->key && X509_check_private_key(cert, gen->key.get()) != 1) {
                ERR_clear_error();
                loader.error(kKeyFile, "la clé ne correspond pas au certificat " + tls::subject_of(cert));
            }
            if (X509_check_purpose(const_cast<X509*>(cert), purpose, 0) != 1) {
                loader.error(kCertFile, std::string("usage incompatible avec le rôle ") + role_name);
            }
            if (!gen->chain.empty() && X509_check_issued(gen->chain.front().get(), const_cast<X509*>(cert)) != X509_V_OK) {
                loader.error(kChainFile, "le premier certificat n'est pas l'émetteur de cert.pem");
            }
            for (const auto& ca : gen->chain) check_dates(loader, kChainFile, ca.get(), req.expiry_warning);
            // Avec des racines disponibles, la chaîne complète doit se vérifier.
            if (!gen->trust_roots.empty() && !gen->chain.empty()) {
                if (auto failure = verify(cert, gen->chain, gen->trust_roots, purpose)) {
                    loader.error(kCertFile, "chaîne invalide : " + *failure);
                }
            }
        }
    }

    if (result.errors.empty()) result.generation = std::move(gen);
    return result;
}

LoadResult load_current_generation(const fs::path& pki_root, const Requirements& req) {
    const auto pointer = pki_root / "current";
    auto content = read_file(pointer);
    if (!content) {
        LoadResult result;
        result.errors.push_back({pointer.string(), "fichier absent ou illisible"});
        return result;
    }
    while (!content->empty() && (content->back() == '\n' || content->back() == '\r' || content->back() == ' ')) {
        content->pop_back();
    }
    if (!valid_generation_name(*content)) {
        LoadResult result;
        result.errors.push_back({pointer.string(), "nom de génération invalide « " + *content + " »"});
        return result;
    }
    return load_generation(pki_root / *content, req);
}

std::optional<Requirements> requirements_for(const Config& config) {
    const bool tls = config.ports.count(PortKind::tls) != 0;
    const bool mtls = config.ports.count(PortKind::mtls) != 0;
    if (!tls && !mtls) return std::nullopt;

    Requirements req;
    if (config.credentials) req.expiry_warning = config.credentials->expiry_warning;
    if (config.mode == Mode::server) {
        req.role = Role::server;
        req.identity = true;  // le serveur présente toujours son certificat
        req.trust = mtls;     // il vérifie les clients en mTLS
    } else {
        req.role = Role::client;
        req.trust = true;     // le client vérifie toujours le serveur
        req.identity = mtls;  // il présente son certificat en mTLS
    }
    return req;
}

}  // namespace tlsrelay::pki
