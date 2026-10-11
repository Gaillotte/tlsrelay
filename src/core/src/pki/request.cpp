#include "tlsrelay/pki/request.hpp"

#include "tlsrelay/endpoint.hpp"

#include "files.hpp"

#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <fstream>

namespace tlsrelay::pki {
namespace {

namespace fs = std::filesystem;
using detail::fail;

// Numéro d'un nom de génération « vN », ou -1.
long generation_number(const std::string& name) {
    if (name.size() < 2 || name[0] != 'v' || name.size() > 10) return -1;
    if (!std::all_of(name.begin() + 1, name.end(), [](char c) { return c >= '0' && c <= '9'; })) return -1;
    return std::stol(name.substr(1));
}

std::vector<std::pair<long, std::string>> generations(const fs::path& pki_root) {
    std::vector<std::pair<long, std::string>> out;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(pki_root, ec)) {
        if (!entry.is_directory()) continue;
        const auto name = entry.path().filename().string();
        if (const long n = generation_number(name); n >= 0) out.emplace_back(n, name);
    }
    std::sort(out.begin(), out.end());
    return out;
}

bool valid_dns_name(const std::string& name) {
    if (name.empty() || name.size() > 253) return false;
    std::size_t label = 0;
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
            continue;
        }
        const bool wildcard = c == '*' && i == 0 && name.size() > 2 && name[1] == '.';
        if (!wildcard && !std::isalnum(static_cast<unsigned char>(c)) && c != '-') return false;
        if (++label > 63) return false;
    }
    return label > 0;
}

std::optional<std::string> current_name(const fs::path& pki_root) {
    std::ifstream in(pki_root / "current");
    std::string name;
    if (!in || !std::getline(in, name)) return std::nullopt;
    while (!name.empty() && (name.back() == '\r' || name.back() == ' ')) name.pop_back();
    if (generation_number(name) < 0) return std::nullopt;
    return name;
}

void copy_in(const fs::path& source, const fs::path& target) {
    detail::write_file(target, detail::read_file(source));
}

}  // namespace

std::string SubjectAltNames::to_openssl() const {
    std::string out;
    for (const auto& d : dns) out += (out.empty() ? "" : ",") + std::string("DNS:") + d;
    for (const auto& i : ip) out += (out.empty() ? "" : ",") + std::string("IP:") + i;
    return out;
}

std::optional<SubjectAltNames> parse_sans(const std::vector<std::string>& items, std::string& error) {
    SubjectAltNames sans;
    for (const auto& raw : items) {
        // Plusieurs valeurs peuvent être séparées par des virgules.
        std::size_t start = 0;
        while (start <= raw.size()) {
            const auto end = raw.find(',', start);
            std::string item = raw.substr(start, end == std::string::npos ? std::string::npos : end - start);
            start = end == std::string::npos ? raw.size() + 1 : end + 1;
            if (item.empty()) continue;
            std::string kind;
            if (const auto colon = item.find(':'); colon != std::string::npos && colon <= 3) {
                kind = item.substr(0, colon);
                std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c) { return std::tolower(c); });
                if (kind == "dns" || kind == "ip") item = item.substr(colon + 1);
                else kind.clear();
            }
            if (kind.empty()) kind = is_ip_literal(item) ? "ip" : "dns";
            if (kind == "ip") {
                if (!is_ip_literal(item)) {
                    error = "adresse IP invalide « " + item + " »";
                    return std::nullopt;
                }
                sans.ip.push_back(item);
            } else {
                if (!valid_dns_name(item)) {
                    error = "nom DNS invalide « " + item + " »";
                    return std::nullopt;
                }
                sans.dns.push_back(item);
            }
        }
    }
    return sans;
}

std::string next_generation_name(const fs::path& pki_root) {
    const auto list = generations(pki_root);
    return "v" + std::to_string(list.empty() ? 1 : list.back().first + 1);
}

std::optional<std::string> pending_generation(const fs::path& pki_root) {
    const auto list = generations(pki_root);
    for (auto it = list.rbegin(); it != list.rend(); ++it) {
        const auto dir = pki_root / it->second;
        std::error_code ec;
        if (fs::exists(dir / "key.pem", ec) && fs::exists(dir / "request.csr", ec) && !fs::exists(dir / "cert.pem", ec)) {
            return it->second;
        }
    }
    return std::nullopt;
}

CsrResult generate_csr(const fs::path& pki_root, const std::string& subject, const SubjectAltNames& sans) {
    std::string error;
    auto name = tls::parse_dn(subject, error);
    if (!name) throw std::runtime_error("sujet invalide : " + error);
    if (X509_NAME_get_index_by_NID(name.get(), NID_commonName, -1) < 0) {
        throw std::runtime_error("sujet invalide : CN obligatoire");
    }

    auto key = detail::generate_ec_key("P-256");
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(X509_REQ_new(), X509_REQ_free);
    if (!req || !X509_REQ_set_version(req.get(), 0) || !X509_REQ_set_subject_name(req.get(), name.get()) ||
        !X509_REQ_set_pubkey(req.get(), key.get())) {
        fail("création de la demande impossible");
    }
    if (!sans.empty()) {
        std::unique_ptr<STACK_OF(X509_EXTENSION), void (*)(STACK_OF(X509_EXTENSION)*)> exts(
            sk_X509_EXTENSION_new_null(), [](STACK_OF(X509_EXTENSION)* s) { sk_X509_EXTENSION_pop_free(s, X509_EXTENSION_free); });
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, sans.to_openssl().c_str());
        if (!ext) fail("SAN invalides");
        sk_X509_EXTENSION_push(exts.get(), ext);
        if (!X509_REQ_add_extensions(req.get(), exts.get())) fail("SAN invalides");
    }
    if (X509_REQ_sign(req.get(), key.get(), EVP_sha256()) <= 0) fail("signature de la demande impossible");

    detail::make_private_dir(pki_root);
    const auto generation = next_generation_name(pki_root);
    const auto dir = pki_root / generation;
    detail::make_private_dir(dir);

    tls::BioPtr key_bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
        fail("encodage de la clé impossible");
    }
    detail::write_file(dir / "key.pem", detail::bio_text(key_bio.get()), true);
    tls::BioPtr req_bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_X509_REQ(req_bio.get(), req.get())) fail("encodage de la demande impossible");
    detail::write_file(dir / "request.csr", detail::bio_text(req_bio.get()));
    return {generation, dir / "request.csr", tls::name_to_string(name.get())};
}

InstallResult install(const fs::path& pki_root, std::optional<std::string> generation, const InstallFiles& files,
                      const Requirements& req) {
    // Fichier fourni explicitement, sinon pris dans le répertoire « from ».
    auto pick = [&](const std::optional<fs::path>& explicit_path, const char* name) -> std::optional<fs::path> {
        if (explicit_path) return explicit_path;
        if (files.from) {
            std::error_code ec;
            if (fs::exists(*files.from / name, ec)) return *files.from / name;
        }
        return std::nullopt;
    };
    const auto cert = pick(files.cert, "cert.pem");
    const auto chain = pick(files.chain, "chain.pem");
    auto roots = pick(files.roots, "trust-roots.pem");
    auto issuer = pick(files.issuer, "trust-issuer.pem");

    if (!generation) {
        if (req.identity) {
            generation = pending_generation(pki_root);
            if (!generation) throw std::runtime_error("aucune demande en attente dans " + pki_root.string() +
                                                      " (créer d'abord la clé : pki gen-csr)");
        } else {
            generation = next_generation_name(pki_root);
        }
    }
    if (generation_number(*generation) < 0) throw std::runtime_error("nom de génération invalide « " + *generation + " »");
    const auto dir = pki_root / *generation;
    std::error_code ec;
    if (fs::exists(dir / "cert.pem", ec)) {
        throw std::runtime_error("la génération " + *generation + " est déjà complète (cert.pem présent)");
    }

    if (req.identity) {
        if (!fs::exists(dir / "key.pem", ec)) {
            throw std::runtime_error("pas de clé dans " + dir.string() + " (pki gen-csr)");
        }
        if (!cert || !chain) throw std::runtime_error("certificat et chaîne obligatoires (--cert et --chain, ou --from)");
    }
    // Fichiers de confiance absents : ceux de la génération courante.
    if (!roots || !issuer) {
        const auto current = current_name(pki_root);
        if (!current) {
            throw std::runtime_error("racines et AC attendue obligatoires (--roots et --issuer) : pas de génération courante");
        }
        if (!roots && fs::exists(pki_root / *current / "trust-roots.pem", ec)) roots = pki_root / *current / "trust-roots.pem";
        if (!issuer && fs::exists(pki_root / *current / "trust-issuer.pem", ec)) {
            issuer = pki_root / *current / "trust-issuer.pem";
        }
    }
    if (req.trust && (!roots || !issuer)) throw std::runtime_error("racines et AC attendue introuvables (--roots, --issuer)");

    detail::make_private_dir(dir);
    if (cert) copy_in(*cert, dir / "cert.pem");
    if (chain) copy_in(*chain, dir / "chain.pem");
    if (roots) copy_in(*roots, dir / "trust-roots.pem");
    if (issuer) copy_in(*issuer, dir / "trust-issuer.pem");

    InstallResult result;
    result.generation = *generation;
    // Garde-fou compris, s'il existe une génération courante.
    result.check = current_name(pki_root) ? check_candidate(pki_root, *generation, req) : load_generation(dir, req);
    return result;
}

}  // namespace tlsrelay::pki
