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

    // Les racines de confiance sont lues dès que le fichier est présent, même
    // si elles ne servent pas à vérifier un pair : le garde-fou de rotation
    // s'en sert pour contrôler la nouvelle identité (rotation_guard).
    if (!req.trust && fs::exists(dir / kRootsFile)) {
        gen->trust_roots = loader.certificates(kRootsFile, false);
    }
    if (req.trust) {
        gen->trust_roots = loader.certificates(kRootsFile, true);
        for (const auto& root : gen->trust_roots) {
            if (X509_check_ca(root.get()) < 1) loader.error(kRootsFile, "n'est pas une AC : " + tls::subject_of(root.get()));
            check_dates(loader, kRootsFile, root.get(), req.expiry_warning);
        }
        // Une AC attendue par racine : plusieurs pendant un changement de racine (SPEC §7.5).
        gen->trust_issuers = loader.certificates(kIssuerFile, true);
        for (const auto& issuer : gen->trust_issuers) {
            const X509* ca = issuer.get();
            if (X509_check_ca(const_cast<X509*>(ca)) < 1) loader.error(kIssuerFile, "n'est pas une AC : " + tls::subject_of(ca));
            check_dates(loader, kIssuerFile, ca, req.expiry_warning);
            if (!gen->trust_roots.empty()) {
                if (auto failure = verify(ca, {}, gen->trust_roots, 0)) {
                    loader.error(kIssuerFile, tls::subject_of(ca) + " ne se rattache pas aux racines de confiance : " +
                                                  *failure);
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

std::optional<std::string> rotation_guard(const Generation& current, const Generation& next, const Requirements& req) {
    if (current.name == next.name) return std::nullopt;
    // Racines : au moins une en commun, sinon les pairs encore sur l'ancienne
    // génération seraient refusés (étape 1 du changement de racine manquante).
    if (req.trust && !next.shares_root_with(current)) {
        return "aucune racine de confiance commune avec la génération " + current.name +
               " ; pour changer de racine, ajouter d'abord la nouvelle racine (SPEC §7.5)";
    }
    // Identité : le nouveau certificat doit se rattacher à une racine déjà
    // connue de la génération courante, sinon les pairs qui ne connaissent
    // pas encore sa racine ne pourraient plus se connecter.
    if (next.cert) {
        const int purpose = req.role == Role::server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
        if (!current.trust_roots.empty()) {
            if (auto failure = verify(next.cert.get(), next.chain, current.trust_roots, purpose)) {
                return "le nouveau certificat ne se rattache à aucune racine de confiance de la génération " +
                       current.name + " (" + *failure + ") ; pour changer de racine, ajouter d'abord la nouvelle "
                       "racine (SPEC §7.5)";
            }
        } else if (!current.chain.empty() && !next.chain.empty() &&
                   X509_NAME_cmp(X509_get_issuer_name(current.chain.back().get()),
                                 X509_get_issuer_name(next.chain.back().get())) != 0) {
            return "le nouveau certificat dépend d'une autre racine que la génération " + current.name +
                   " ; ajouter trust-roots.pem (racines connues des pairs) pour permettre un changement de racine";
        }
    }
    return std::nullopt;
}

LoadResult check_candidate(const fs::path& pki_root, const std::string& name, const Requirements& req) {
    if (!valid_generation_name(name)) {
        LoadResult result;
        result.errors.push_back({name, "nom de génération invalide"});
        return result;
    }
    auto result = load_generation(pki_root / name, req);
    if (!result.generation) return result;

    const auto current = load_current_generation(pki_root, req);
    if (!current.generation) {
        result.warnings.push_back({(pki_root / "current").string(),
                                   "génération courante illisible : garde-fou des racines non vérifié"});
    } else if (auto problem = rotation_guard(*current.generation, *result.generation, req)) {
        result.errors.push_back({(pki_root / name).string(), "garde-fou de rotation : " + *problem});
        result.generation.reset();
    }
    return result;
}

void activate(const fs::path& pki_root, const std::string& name) {
    if (!valid_generation_name(name)) {
        throw fs::filesystem_error("nom de génération invalide", pki_root / name,
                                   std::make_error_code(std::errc::invalid_argument));
    }
    const auto tmp = pki_root / "current.tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out << name << "\n";
        if (!out) throw fs::filesystem_error("écriture impossible", tmp, std::make_error_code(std::errc::io_error));
    }
    fs::rename(tmp, pki_root / "current");  // remplacement atomique
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
