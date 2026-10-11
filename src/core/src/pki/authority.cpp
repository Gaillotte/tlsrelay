#include "tlsrelay/pki/authority.hpp"

#include "files.hpp"

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
constexpr const char* kIndexHeader = "# série\trôle\tétat\tfin de validité\tsujet\n";

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
    std::strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%SZ", &tm);
    return buffer;
}

void write_index(const fs::path& dir, const std::vector<IndexEntry>& entries) {
    std::string out = kIndexHeader;
    for (const auto& e : entries) {
        out += e.serial + "\t" + e.role + "\t" + e.status + "\t" + e.not_after + "\t" + e.subject + "\n";
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
}

std::vector<IndexEntry> list_issued(const fs::path& dir) {
    std::vector<IndexEntry> entries;
    std::istringstream in(detail::read_file(dir / kIndex));
    for (std::string line; std::getline(in, line);) {
        if (line.empty() || line[0] == '#') continue;
        IndexEntry e;
        std::istringstream fields(line);
        std::getline(fields, e.serial, '\t');
        std::getline(fields, e.role, '\t');
        std::getline(fields, e.status, '\t');
        std::getline(fields, e.not_after, '\t');
        std::getline(fields, e.subject);
        entries.push_back(std::move(e));
    }
    return entries;
}

IssuedCertificate sign_request(const fs::path& dir, const std::string& passphrase, const SignRequest& request) {
    // Demande : signature valide (preuve de possession de la clé), clé P-256.
    tls::BioPtr bio(BIO_new_mem_buf(request.csr_pem.data(), static_cast<int>(request.csr_pem.size())));
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr),
                                                            X509_REQ_free);
    if (!req) fail("demande de signature illisible");
    EVP_PKEY* public_key = X509_REQ_get0_pubkey(req.get());
    if (!public_key || X509_REQ_verify(req.get(), public_key) != 1) {
        fail("signature de la demande invalide");
    }
    char group[64] = {};
    std::size_t group_len = 0;
    if (EVP_PKEY_get_base_id(public_key) != EVP_PKEY_EC ||
        !EVP_PKEY_get_utf8_string_param(public_key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &group_len) ||
        std::string(group) != "prime256v1") {
        tls::take_openssl_errors();
        throw std::runtime_error("clé refusée : ECDSA P-256 attendue (politique de l'AC)");
    }
    const X509_NAME* subject = X509_REQ_get_subject_name(req.get());
    if (X509_NAME_get_index_by_NID(const_cast<X509_NAME*>(subject), NID_commonName, -1) < 0) {
        throw std::runtime_error("sujet refusé : CN obligatoire");
    }
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
    if (STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req.get())) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); ++i) {
            const auto nid = OBJ_obj2nid(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(exts, i)));
            issued.ignored_extensions.push_back(nid == NID_undef ? "?" : OBJ_nid2sn(nid));
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

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
    entries.push_back({issued.serial, role_name(request.role), "valide", issued.not_after, subject_text});
    write_index(dir, entries);
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

}  // namespace tlsrelay::pki
