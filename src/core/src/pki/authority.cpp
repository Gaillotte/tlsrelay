#include "tlsrelay/pki/authority.hpp"

#include "files.hpp"

#include "tlsrelay/pki/audit.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif
#include <fstream>
#include <sstream>
#include <utility>
#include <vector>

namespace tlsrelay::pki {
namespace {

namespace fs = std::filesystem;
using detail::fail;

struct CaFiles {
    const char* key;
    const char* cert;
};
constexpr CaFiles kRoot{"root.key.pem", "root.cert.pem"};
constexpr CaFiles kServers{"servers.key.pem", "servers.cert.pem"};
constexpr CaFiles kClients{"clients.key.pem", "clients.cert.pem"};
constexpr const char* kIndex = "index.tsv";
constexpr const char* kIndexHeader =
    "# série\trôle\tétat\tfin de validité\tsujet\tdate de révocation\tmotif de révocation\n";
constexpr const char* kCrlFile = "crl.pem";
constexpr const char* kCrlNumberFile = "crlnumber";

// Paramètres scrypt : 16 Mio de mémoire (sous la limite par défaut d'OpenSSL au déchiffrement).
constexpr std::uint64_t kScryptN = 1 << 14;
constexpr std::uint64_t kScryptR = 8;
constexpr std::uint64_t kScryptP = 1;

#ifdef _WIN32
// Clé d'AC : ACL protégée (sans héritage) pour SYSTEM, les Administrateurs et
// le compte qui crée l'AC, à l'image des droits 0600 sous Linux.
void restrict_to_owner(const fs::path& path) {
    std::wstring sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> buffer(size);
        LPWSTR sid = nullptr;
        if (size && GetTokenInformation(token, TokenUser, buffer.data(), size, &size) &&
            ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) {
            sddl += L"(A;;FA;;;" + std::wstring(sid) + L")";
            LocalFree(sid);
        }
        CloseHandle(token);
    }
    PSECURITY_DESCRIPTOR sd = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    const bool ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr) &&
                    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) &&
                    SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                          nullptr, dacl, nullptr) == ERROR_SUCCESS;
    if (sd) LocalFree(sd);
    if (!ok) throw std::runtime_error("droits d'accès de " + path.string() + " non appliqués");
}
#else
void restrict_to_owner(const fs::path&) {}  // déjà en 0600 (write_file)
#endif

void write_ca_key(const fs::path& path, const std::string& pem) {
    detail::write_file(path, pem, true);
    restrict_to_owner(path);
}

std::string encrypt_key(EVP_PKEY* key, const std::string& passphrase) {
    X509_ALGOR* pbe = PKCS5_pbe2_set_scrypt(EVP_aes_256_cbc(), nullptr, 0, nullptr, kScryptN, kScryptR, kScryptP);
    if (!pbe) fail("paramètres de chiffrement de la clé indisponibles");
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> p8(EVP_PKEY2PKCS8(key),
                                                                                PKCS8_PRIV_KEY_INFO_free);
    X509_SIG* sig = p8 ? PKCS8_set0_pbe(passphrase.data(), static_cast<int>(passphrase.size()), p8.get(), pbe) : nullptr;
    if (!sig) {
        X509_ALGOR_free(pbe);  // non repris en cas d'échec
        fail("chiffrement de la clé impossible");
    }
    std::unique_ptr<X509_SIG, decltype(&X509_SIG_free)> holder(sig, X509_SIG_free);
    tls::BioPtr bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_PKCS8(bio.get(), sig)) fail("encodage de la clé impossible");
    return detail::bio_text(bio.get());
}

tls::EvpPkeyPtr load_key(const fs::path& path, const std::string& passphrase) {
    const auto pem = detail::read_file(path);
    // Une clé non chiffrée serait lue sans phrase de passe : refusée.
    if (pem.find("ENCRYPTED PRIVATE KEY") == std::string::npos) {
        throw std::runtime_error(path.string() + " : clé non chiffrée refusée");
    }
    tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    tls::EvpPkeyPtr key(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast<char*>(passphrase.c_str())));
    if (!key) {
        tls::take_openssl_errors();
        throw std::runtime_error("phrase de passe incorrecte (ou clé illisible) : " + path.string());
    }
    return key;
}

tls::X509Ptr load_cert(const fs::path& path) { return detail::cert_from_pem(detail::read_file(path), path.string()); }

void add_extension(X509* cert, X509V3_CTX* ctx, int nid, const std::string& value) {
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, ctx, nid, value.c_str());
    if (!ext) fail(std::string("extension ") + OBJ_nid2sn(nid) + " invalide");
    const int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    if (!ok) fail("ajout d'extension impossible");
}

struct CertSpec {
    const X509_NAME* subject = nullptr;
    EVP_PKEY* public_key = nullptr;
    const X509* issuer = nullptr;  // nullptr : auto-signé
    EVP_PKEY* signer = nullptr;
    long days = 365;
    std::string serial_hex;
    std::vector<std::pair<int, std::string>> extensions;  // dans l'ordre ; SKI avant AKI
};

tls::X509Ptr build_certificate(const CertSpec& spec) {
    tls::X509Ptr cert(X509_new());
    if (!cert || !X509_set_version(cert.get(), 2)) fail("création du certificat impossible");

    BIGNUM* bn = nullptr;
    if (!BN_hex2bn(&bn, spec.serial_hex.c_str())) fail("numéro de série invalide");
    ASN1_INTEGER* serial = BN_to_ASN1_INTEGER(bn, nullptr);
    BN_free(bn);
    const int serial_ok = serial && X509_set_serialNumber(cert.get(), serial);
    ASN1_INTEGER_free(serial);
    if (!serial_ok) fail("numéro de série invalide");

    if (!X509_set_subject_name(cert.get(), const_cast<X509_NAME*>(spec.subject)) ||
        !X509_set_issuer_name(cert.get(), spec.issuer ? X509_get_subject_name(spec.issuer)
                                                     : const_cast<X509_NAME*>(spec.subject)) ||
        !X509_set_pubkey(cert.get(), spec.public_key)) {
        fail("création du certificat impossible");
    }
    // Une minute de marge pour les horloges légèrement en avance.
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_time_adj_ex(X509_getm_notAfter(cert.get()), static_cast<int>(spec.days), 0, nullptr);
    // Jamais au-delà de la fin de validité de l'AC qui signe.
    if (spec.issuer && ASN1_TIME_compare(X509_get0_notAfter(cert.get()), X509_get0_notAfter(spec.issuer)) > 0) {
        X509_set1_notAfter(cert.get(), X509_get0_notAfter(spec.issuer));
    }

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, spec.issuer ? const_cast<X509*>(spec.issuer) : cert.get(), cert.get(), nullptr, nullptr, 0);
    for (const auto& [nid, value] : spec.extensions) add_extension(cert.get(), &ctx, nid, value);

    if (X509_sign(cert.get(), spec.signer, EVP_sha384()) <= 0) fail("signature du certificat impossible");
    return cert;
}

tls::X509NamePtr make_name(const std::string& organization, const std::string& common_name) {
    tls::X509NamePtr name(X509_NAME_new());
    auto add = [&](const char* field, const std::string& value) {
        if (!X509_NAME_add_entry_by_txt(name.get(), field, MBSTRING_UTF8,
                                        reinterpret_cast<const unsigned char*>(value.c_str()), -1, -1, 0)) {
            fail(std::string("nom invalide : ") + field + "=" + value);
        }
    };
    add("O", organization);
    add("CN", common_name);
    return name;
}

std::string now_text() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[32];
    (void)std::strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%SZ", &tm);
    return buffer;
}

void write_index(const fs::path& dir, const std::vector<IndexEntry>& entries) {
    std::string out = kIndexHeader;
    for (const auto& e : entries) {
        out += e.serial + "\t" + e.role + "\t" + e.status + "\t" + e.not_after + "\t" + e.subject + "\t" +
               e.revoked_at + "\t" + e.reason + "\n";
    }
    const auto tmp = dir / (std::string(kIndex) + ".tmp");
    detail::write_file(tmp, out);
    fs::rename(tmp, dir / kIndex);
}

const char* role_name(Role role) { return role == Role::server ? "server" : "client"; }

}  // namespace

void init_authority(const fs::path& dir, const std::string& passphrase, const AuthorityOptions& options) {
    if (passphrase.size() < kMinPassphrase) {
        throw std::runtime_error("phrase de passe trop courte (" + std::to_string(kMinPassphrase) +
                                 " caractères au moins)");
    }
    std::error_code ec;
    if (fs::exists(dir, ec) && !fs::is_empty(dir, ec)) {
        throw std::runtime_error(dir.string() + " n'est pas vide : une AC existe peut-être déjà");
    }
    detail::make_private_dir(dir);
    detail::make_private_dir(dir / "issued");

    const auto& org = options.organization;
    auto root_key = detail::generate_ec_key("P-384");
    const auto root_name = make_name(org, org + " AC Racine");
    auto root = build_certificate({root_name.get(), root_key.get(), nullptr, root_key.get(), options.root_days,
                                   detail::random_serial_hex(),
                                   {{NID_basic_constraints, "critical,CA:TRUE"},
                                    {NID_key_usage, "critical,keyCertSign,cRLSign"},
                                    {NID_subject_key_identifier, "hash"},
                                    {NID_authority_key_identifier, "keyid:always"}}});

    auto make_ca = [&](const std::string& cn, const char* eku, const CaFiles& files) {
        auto key = detail::generate_ec_key("P-384");
        const auto name = make_name(org, org + " " + cn);
        auto cert = build_certificate({name.get(), key.get(), root.get(), root_key.get(), options.ca_days,
                                       detail::random_serial_hex(),
                                       {{NID_basic_constraints, "critical,CA:TRUE,pathlen:0"},
                                        {NID_key_usage, "critical,keyCertSign,cRLSign"},
                                        {NID_ext_key_usage, eku},
                                        {NID_subject_key_identifier, "hash"},
                                        {NID_authority_key_identifier, "keyid:always"}}});
        write_ca_key(dir / files.key, encrypt_key(key.get(), passphrase));
        detail::write_file(dir / files.cert, detail::pem_of(cert.get()));
    };
    write_ca_key(dir / kRoot.key, encrypt_key(root_key.get(), passphrase));
    detail::write_file(dir / kRoot.cert, detail::pem_of(root.get()));
    make_ca("AC Serveurs", "serverAuth", kServers);
    make_ca("AC Clients", "clientAuth", kClients);
    write_index(dir, {});
    append_audit(dir, "init", "organisation=" + org + " racine=" + tls::subject_of(root.get()) + " fin=" +
                                  tls::not_after_of(root.get()));
}

std::vector<IndexEntry> list_issued(const fs::path& dir) {
    std::vector<IndexEntry> entries;
    std::istringstream in(detail::read_file(dir / kIndex));
    for (std::string line; std::getline(in, line);) {
        if (line.empty() || line[0] == '#') continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::vector<std::string> fields;
        for (std::size_t start = 0;;) {
            const auto tab = line.find('\t', start);
            fields.push_back(line.substr(start, tab - start));
            if (tab == std::string::npos) break;
            start = tab + 1;
        }
        if (fields.size() < 5) continue;
        IndexEntry e{fields[0], fields[1], fields[2], fields[3], fields[4], {}, {}};
        // Inventaire d'avant la livraison 1.1 : cinq colonnes, sans révocation.
        if (fields.size() >= 7) {
            e.revoked_at = fields[5];
            e.reason = fields[6];
        }
        entries.push_back(std::move(e));
    }
    return entries;
}

namespace {

using RequestPtr = std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)>;

RequestPtr parse_request(const std::string& csr_pem) {
    tls::BioPtr bio(BIO_new_mem_buf(csr_pem.data(), static_cast<int>(csr_pem.size())));
    RequestPtr req(PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr), X509_REQ_free);
    if (!req) fail("demande de signature illisible");
    // Demande : signature valide (preuve de possession de la clé), clé P-256.
    EVP_PKEY* public_key = X509_REQ_get0_pubkey(req.get());
    if (!public_key || X509_REQ_verify(req.get(), public_key) != 1) fail("signature de la demande invalide");
    char group[64] = {};
    std::size_t group_len = 0;
    if (EVP_PKEY_get_base_id(public_key) != EVP_PKEY_EC ||
        !EVP_PKEY_get_utf8_string_param(public_key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &group_len) ||
        std::string(group) != "prime256v1") {
        tls::take_openssl_errors();
        throw std::runtime_error("clé refusée : ECDSA P-256 attendue (politique de l'AC)");
    }
    if (X509_NAME_get_index_by_NID(X509_REQ_get_subject_name(req.get()), NID_commonName, -1) < 0) {
        throw std::runtime_error("sujet refusé : CN obligatoire");
    }
    return req;
}

std::vector<std::string> requested_extensions(X509_REQ* req) {
    std::vector<std::string> names;
    if (STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req)) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
            const auto nid = OBJ_obj2nid(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(exts, i)));
            names.push_back(nid == NID_undef ? "?" : OBJ_nid2sn(nid));
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    tls::take_openssl_errors();
    return names;
}

}  // namespace

RequestInfo inspect_request(const std::string& csr_pem) {
    auto req = parse_request(csr_pem);
    return {tls::name_to_string(X509_REQ_get_subject_name(req.get())), requested_extensions(req.get())};
}

IssuedCertificate sign_request(const fs::path& dir, const std::string& passphrase, const SignRequest& request) {
    auto req = parse_request(request.csr_pem);
    EVP_PKEY* public_key = X509_REQ_get0_pubkey(req.get());
    const X509_NAME* subject = X509_REQ_get_subject_name(req.get());
    if (request.role == Role::server && request.sans.empty()) {
        throw std::runtime_error("certificat serveur : au moins un SAN (--san) est obligatoire");
    }
    if (request.days < 1 || request.days > 3650) throw std::runtime_error("durée invalide (1 à 3650 jours)");

    // Sujet déjà attribué à un certificat en cours de validité.
    const auto subject_text = tls::name_to_string(subject);
    auto entries = list_issued(dir);
    const auto now = now_text();
    bool replaced = false;
    for (auto& e : entries) {
        if (e.status != "valide" || e.subject != subject_text || e.not_after <= now) continue;
        if (!request.renew) {
            throw std::runtime_error("sujet « " + subject_text + " » déjà attribué (série " + e.serial +
                                     ") : utiliser --renew pour un renouvellement");
        }
        if (e.role != role_name(request.role)) {
            throw std::runtime_error("sujet « " + subject_text + " » attribué au rôle " + e.role);
        }
        e.status = "remplacé";
        replaced = true;
    }
    if (request.renew && !replaced) {
        throw std::runtime_error("--renew : aucun certificat en cours de validité pour « " + subject_text + " »");
    }

    // Extensions demandées : ignorées, la politique de l'AC s'applique.
    IssuedCertificate issued;
    issued.ignored_extensions = requested_extensions(req.get());

    const auto& ca_files = request.role == Role::server ? kServers : kClients;
    const auto& peer_files = request.role == Role::server ? kClients : kServers;
    auto ca_cert = load_cert(dir / ca_files.cert);
    auto ca_key = load_key(dir / ca_files.key, passphrase);
    if (X509_check_private_key(ca_cert.get(), ca_key.get()) != 1) fail("clé et certificat de l'AC incohérents");

    std::vector<std::pair<int, std::string>> extensions = {
        {NID_basic_constraints, "critical,CA:FALSE"},
        {NID_key_usage, "critical,digitalSignature"},
        {NID_ext_key_usage, request.role == Role::server ? "serverAuth" : "clientAuth"},
        {NID_subject_key_identifier, "hash"},
        {NID_authority_key_identifier, "keyid:always"}};
    if (!request.sans.empty()) extensions.emplace_back(NID_subject_alt_name, request.sans.to_openssl());

    issued.serial = detail::random_serial_hex();
    auto cert = build_certificate({subject, public_key, ca_cert.get(), ca_key.get(), request.days, issued.serial,
                                   std::move(extensions)});
    issued.subject = subject_text;
    issued.not_after = tls::not_after_of(cert.get());
    issued.cert_pem = detail::pem_of(cert.get());
    issued.chain_pem = detail::pem_of(ca_cert.get());
    issued.roots_pem = detail::read_file(dir / kRoot.cert);
    issued.issuer_pem = detail::read_file(dir / peer_files.cert);

    detail::write_file(dir / "issued" / (issued.serial + ".pem"), issued.cert_pem);
    entries.push_back({issued.serial, role_name(request.role), "valide", issued.not_after, subject_text, {}, {}});
    write_index(dir, entries);
    append_audit(dir, "sign", "série=" + issued.serial + " rôle=" + role_name(request.role) + " sujet=" + subject_text +
                                  " fin=" + issued.not_after + (request.renew ? " renouvellement" : ""));
    return issued;
}

void write_bundle(const fs::path& out, const IssuedCertificate& issued) {
    std::error_code ec;
    fs::create_directories(out, ec);
    if (ec) throw std::runtime_error("création impossible : " + out.string() + " : " + ec.message());
    detail::write_file(out / "cert.pem", issued.cert_pem);
    detail::write_file(out / "chain.pem", issued.chain_pem);
    detail::write_file(out / "trust-roots.pem", issued.roots_pem);
    detail::write_file(out / "trust-issuer.pem", issued.issuer_pem);
}

std::string_view to_string(RevocationReason reason) {
    switch (reason) {
        case RevocationReason::unspecified: return "unspecified";
        case RevocationReason::key_compromise: return "keyCompromise";
        case RevocationReason::superseded: return "superseded";
        case RevocationReason::cessation_of_operation: return "cessationOfOperation";
    }
    return "unspecified";
}

std::optional<RevocationReason> parse_revocation_reason(std::string_view text) {
    for (auto r : {RevocationReason::unspecified, RevocationReason::key_compromise, RevocationReason::superseded,
                   RevocationReason::cessation_of_operation}) {
        if (text == to_string(r)) return r;
    }
    return std::nullopt;
}

IndexEntry revoke_certificate(const fs::path& dir, const std::string& serial, RevocationReason reason) {
    std::string wanted = serial;
    for (auto& c : wanted) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    auto entries = list_issued(dir);
    for (auto& e : entries) {
        if (e.serial != wanted) continue;
        if (e.status == "révoqué") throw std::runtime_error("certificat " + e.serial + " déjà révoqué le " + e.revoked_at);
        e.status = "révoqué";
        e.revoked_at = now_text();
        e.reason = std::string(to_string(reason));
        write_index(dir, entries);
        append_audit(dir, "revoke", "série=" + e.serial + " rôle=" + e.role + " sujet=" + e.subject + " motif=" + e.reason);
        return e;
    }
    throw std::runtime_error("série " + serial + " inconnue de l'inventaire");
}

namespace {

using CrlPtr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;

// "2026-10-12 08:00:00Z" (inventaire) vers ASN1_TIME.
bool set_index_time(ASN1_TIME* t, const std::string& text) {
    std::string compact;
    for (char c : text) {
        if (c != '-' && c != ' ' && c != ':') compact += c;
    }
    return ASN1_TIME_set_string_X509(t, compact.c_str()) == 1;
}

int reason_code(const std::string& reason) {
    if (reason == "keyCompromise") return CRL_REASON_KEY_COMPROMISE;
    if (reason == "superseded") return CRL_REASON_SUPERSEDED;
    if (reason == "cessationOfOperation") return CRL_REASON_CESSATION_OF_OPERATION;
    return CRL_REASON_UNSPECIFIED;
}

std::string build_crl(X509* ca, EVP_PKEY* key, const std::vector<IndexEntry>& revoked, std::uint64_t number, int days,
                      std::string& next_update) {
    CrlPtr crl(X509_CRL_new(), X509_CRL_free);
    if (!crl || !X509_CRL_set_version(crl.get(), 1) || !X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca))) {
        fail("création de la CRL impossible");
    }
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last(X509_gmtime_adj(nullptr, -60), ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next(X509_time_adj_ex(nullptr, days, 0, nullptr),
                                                               ASN1_TIME_free);
    if (!last || !next) fail("dates de la CRL invalides");
    if (ASN1_TIME_compare(next.get(), X509_get0_notAfter(ca)) > 0) next.reset(ASN1_STRING_dup(X509_get0_notAfter(ca)));
    if (!X509_CRL_set1_lastUpdate(crl.get(), last.get()) || !X509_CRL_set1_nextUpdate(crl.get(), next.get())) {
        fail("dates de la CRL invalides");
    }

    for (const auto& e : revoked) {
        X509_REVOKED* r = X509_REVOKED_new();
        BIGNUM* bn = nullptr;
        ASN1_INTEGER* serial = BN_hex2bn(&bn, e.serial.c_str()) ? BN_to_ASN1_INTEGER(bn, nullptr) : nullptr;
        BN_free(bn);
        std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> when(ASN1_TIME_new(), ASN1_TIME_free);
        bool ok = r && serial && when && set_index_time(when.get(), e.revoked_at) &&
                  X509_REVOKED_set_serialNumber(r, serial) && X509_REVOKED_set_revocationDate(r, when.get());
        ASN1_INTEGER_free(serial);
        if (ok && reason_code(e.reason) != CRL_REASON_UNSPECIFIED) {
            ASN1_ENUMERATED* code = ASN1_ENUMERATED_new();
            ok = code && ASN1_ENUMERATED_set(code, reason_code(e.reason)) &&
                 X509_REVOKED_add1_ext_i2d(r, NID_crl_reason, code, 0, 0) == 1;
            ASN1_ENUMERATED_free(code);
        }
        if (!ok || !X509_CRL_add0_revoked(crl.get(), r)) {
            X509_REVOKED_free(r);
            fail("entrée de CRL invalide pour la série " + e.serial);
        }
    }
    X509_CRL_sort(crl.get());

    ASN1_INTEGER* crl_number = ASN1_INTEGER_new();
    const bool numbered = crl_number && ASN1_INTEGER_set_uint64(crl_number, number) &&
                          X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, crl_number, 0, 0) == 1;
    ASN1_INTEGER_free(crl_number);
    if (!numbered) fail("numéro de CRL invalide");
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca, nullptr, nullptr, crl.get(), 0);
    X509_EXTENSION* aki = X509V3_EXT_conf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always");
    const bool aki_ok = aki && X509_CRL_add_ext(crl.get(), aki, -1) == 1;
    X509_EXTENSION_free(aki);
    if (!aki_ok) fail("identifiant de clé de l'AC dans la CRL");

    if (X509_CRL_sign(crl.get(), key, EVP_sha384()) <= 0) fail("signature de la CRL impossible");
    next_update = tls::time_to_string(X509_CRL_get0_nextUpdate(crl.get()));
    tls::BioPtr bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_X509_CRL(bio.get(), crl.get())) fail("encodage de la CRL impossible");
    return detail::bio_text(bio.get());
}

}  // namespace

CrlInfo publish_crl(const fs::path& dir, const std::string& passphrase, int days) {
    if (days < 1 || days > 366) throw std::runtime_error("durée de validité de la CRL invalide (1 à 366 jours)");
    const auto entries = list_issued(dir);
    std::uint64_t number = 1;
    if (fs::exists(dir / kCrlNumberFile)) {
        const auto text = detail::read_file(dir / kCrlNumberFile);
        number = std::strtoull(text.c_str(), nullptr, 10) + 1;
    }

    CrlInfo info;
    info.number = number;
    for (const auto* files : {&kServers, &kClients}) {
        const std::string role = files == &kServers ? "server" : "client";
        std::vector<IndexEntry> revoked;
        for (const auto& e : entries) {
            if (e.role == role && e.status == "révoqué") revoked.push_back(e);
        }
        auto ca_cert = load_cert(dir / files->cert);
        auto ca_key = load_key(dir / files->key, passphrase);
        if (X509_check_private_key(ca_cert.get(), ca_key.get()) != 1) fail("clé et certificat de l'AC incohérents");
        std::string next;
        info.pem += build_crl(ca_cert.get(), ca_key.get(), revoked, number, days, next);
        info.revoked += revoked.size();
        if (info.next_update.empty() || next < info.next_update) info.next_update = next;
    }
    const auto tmp = dir / (std::string(kCrlFile) + ".tmp");
    detail::write_file(tmp, info.pem);
    fs::rename(tmp, dir / kCrlFile);
    detail::write_file(dir / kCrlNumberFile, std::to_string(number) + "\n");
    append_audit(dir, "crl", "numéro=" + std::to_string(number) + " révoqués=" + std::to_string(info.revoked) +
                                 " prochaine=" + info.next_update);
    return info;
}

bool is_past(const std::string& date) { return !date.empty() && date <= now_text(); }

namespace {

CaCertificate ca_certificate(const fs::path& path) {
    const auto cert = load_cert(path);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (X509_digest(cert.get(), EVP_sha256(), digest, &size) != 1) fail("empreinte de " + path.string());
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string fingerprint;
    for (unsigned i = 0; i < size; ++i) {
        if (i) fingerprint += ':';
        fingerprint += hex[digest[i] >> 4];
        fingerprint += hex[digest[i] & 0xf];
    }
    return {tls::subject_of(cert.get()), tls::not_after_of(cert.get()), fingerprint};
}

}  // namespace

AuthorityInfo describe_authority(const fs::path& dir) {
    std::error_code ec;
    if (!fs::is_regular_file(dir / kRoot.cert, ec) || !fs::is_regular_file(dir / kIndex, ec)) {
        throw std::runtime_error(dir.string() + " n'est pas un répertoire d'AC tlsrelay (root.cert.pem, index.tsv)");
    }
    AuthorityInfo info;
    info.root = ca_certificate(dir / kRoot.cert);
    info.servers = ca_certificate(dir / kServers.cert);
    info.clients = ca_certificate(dir / kClients.cert);
    for (const auto& e : list_issued(dir)) {
        ++info.issued;
        if (e.status == "révoqué") ++info.revoked;
        else if (e.status == "valide" && !is_past(e.not_after)) ++info.valid;
    }
    if (fs::exists(dir / kCrlNumberFile, ec)) {
        info.crl_number = std::strtoull(detail::read_file(dir / kCrlNumberFile).c_str(), nullptr, 10);
    }
    if (fs::exists(dir / kCrlFile, ec)) {
        const auto pem = detail::read_file(dir / kCrlFile);
        tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
        while (X509_CRL* crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) {
            const auto next = tls::time_to_string(X509_CRL_get0_nextUpdate(crl));
            if (info.crl_next_update.empty() || next < info.crl_next_update) info.crl_next_update = next;
            X509_CRL_free(crl);
        }
        tls::take_openssl_errors();
    }
    return info;
}

void write_root_transition(const fs::path& old_dir, const fs::path& new_dir, const fs::path& out) {
    const auto old_info = describe_authority(old_dir);
    const auto new_info = describe_authority(new_dir);
    if (old_info.root.fingerprint == new_info.root.fingerprint) {
        throw std::runtime_error("les deux AC ont la même racine : choisir la nouvelle AC");
    }
    auto both = [&](const char* file) { return detail::read_file(old_dir / file) + detail::read_file(new_dir / file); };
    for (const auto* sub : {"serveur", "client"}) detail::make_private_dir(out / sub);
    // Racines : les deux. AC attendue chez le pair : l'AC Clients des deux
    // racines pour un serveur, l'AC Serveurs des deux racines pour un client.
    detail::write_file(out / "serveur" / "trust-roots.pem", both(kRoot.cert));
    detail::write_file(out / "client" / "trust-roots.pem", both(kRoot.cert));
    detail::write_file(out / "serveur" / "trust-issuer.pem", both(kClients.cert));
    detail::write_file(out / "client" / "trust-issuer.pem", both(kServers.cert));
    std::error_code ec;
    std::string crl;
    for (const auto* dir : {&old_dir, &new_dir}) {
        if (fs::exists(*dir / kCrlFile, ec)) crl += detail::read_file(*dir / kCrlFile);
    }
    if (!crl.empty()) detail::write_file(out / kCrlFile, crl);

    const auto old_ac = old_dir.string();
    const auto new_ac = new_dir.string();
    std::ostringstream text;
    text << "Changement de racine (SPEC §7.5)\n"
         << "  ancienne racine : " << old_info.root.subject << "\n    empreinte SHA-256 " << old_info.root.fingerprint
         << "\n  nouvelle racine : " << new_info.root.subject << "\n    empreinte SHA-256 " << new_info.root.fingerprint
         << "\n\nChaque étape se termine sur TOUTES les instances avant de passer à la suivante. Pour chaque "
            "instance (<conf> : sa configuration ; <rôle> : serveur ou client ; <role> : server ou client) :\n\n"
         << "Étape 1 — pré-confiance (deux racines, ancienne PKI)\n"
         << "  instance : tlsrelay pki gen-csr -c <conf> --subject \"<sujet actuel>\" [--san ...]\n"
         << "  AC       : tlsrelay ca sign --dir " << old_ac << " --role <role> --csr request.csr --renew --out kit1"
         << " [--san ...]\n"
         << "  instance : tlsrelay pki install -c <conf> --from kit1 --roots <rôle>/trust-roots.pem "
            "--issuer <rôle>/trust-issuer.pem\n"
         << "             tlsrelay pki activate -c <conf> <génération>\n\n"
         << "Étape 2 — bascule (nouvelle PKI, deux racines)\n"
         << "  instance : tlsrelay pki gen-csr -c <conf> --subject \"<sujet actuel>\" [--san ...]\n"
         << "  AC       : tlsrelay ca sign --dir " << new_ac << " --role <role> --csr request.csr --out kit2 [--san ...]\n"
         << "  instance : tlsrelay pki install -c <conf> --from kit2 --roots <rôle>/trust-roots.pem "
            "--issuer <rôle>/trust-issuer.pem\n"
         << "             tlsrelay pki activate -c <conf> <génération>\n\n"
         << "Étape 3 — retrait de l'ancienne racine\n"
         << "  instance : tlsrelay pki gen-csr -c <conf> --subject \"<sujet actuel>\" [--san ...]\n"
         << "  AC       : tlsrelay ca sign --dir " << new_ac << " --role <role> --csr request.csr --renew --out kit3"
         << " [--san ...]\n"
         << "  instance : tlsrelay pki install -c <conf> --from kit3   (confiance : nouvelle racine seule)\n"
         << "             tlsrelay pki activate -c <conf> <génération>\n\n";
    if (!crl.empty()) {
        text << "CRL : pendant les étapes 1 et 2, installer crl.pem (CRL des deux AC) sur chaque instance "
                "(tlsrelay pki crl -c <conf> crl.pem) ; après l'étape 3, celles de la nouvelle AC seule.\n";
    }
    text << "Après l'étape 3, l'ancienne AC n'est plus utilisée : l'archiver hors ligne.\n";
    detail::write_file(out / "LISEZMOI.txt", text.str());
    const auto details = "ancienne=" + old_info.root.fingerprint + " nouvelle=" + new_info.root.fingerprint +
                         " paquet=" + out.string();
    append_audit(old_dir, "root-transition", details);
    append_audit(new_dir, "root-transition", details);
}

}  // namespace tlsrelay::pki
