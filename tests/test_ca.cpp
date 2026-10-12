// PKI en ligne de commande (phase 7, SPEC §7.6) : mini-AC, demandes de
// signature, installation d'une génération. La PKI produite par la mini-AC
// sert ensuite à une vraie chaîne mTLS.

#include "tlsrelay/pki/audit.hpp"
#include "tlsrelay/pki/authority.hpp"
#include "tlsrelay/pki/revocation.hpp"
#include "tlsrelay/pki/request.hpp"

#include "support/net_helpers.hpp"
#include "support/test_pki.hpp"

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace testnet;
using namespace tlsrelay;
using pki::Role;
using testpki::TempDir;

namespace {

const std::string kPass = "phrase de passe de test";

std::string read(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

tls::X509Ptr cert_of(const std::string& pem) {
    tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    return tls::X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// Demande construite à la main (clé et extensions au choix) pour tester la politique de l'AC.
std::string custom_csr(const char* algorithm, const char* param, const std::string& cn,
                       const std::vector<std::pair<int, std::string>>& extensions = {}) {
    tls::EvpPkeyPtr key(std::string(algorithm) == "RSA" ? EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", size_t{2048})
                                                        : EVP_PKEY_Q_keygen(nullptr, nullptr, algorithm, param));
    X509_REQ* req = X509_REQ_new();
    X509_NAME* name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_REQ_set_pubkey(req, key.get());
    if (!extensions.empty()) {
        STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
        for (const auto& [nid, value] : extensions) {
            sk_X509_EXTENSION_push(exts, X509V3_EXT_conf_nid(nullptr, nullptr, nid, value.c_str()));
        }
        X509_REQ_add_extensions(req, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    X509_REQ_sign(req, key.get(), EVP_sha256());
    tls::BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509_REQ(bio.get(), req);
    X509_REQ_free(req);
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

pki::SubjectAltNames sans_of(std::vector<std::string> items) {
    std::string error;
    auto sans = pki::parse_sans(items, error);
    EXPECT_TRUE(sans) << error;
    return sans.value_or(pki::SubjectAltNames{});
}

class CaTest : public ::testing::Test {
protected:
    void SetUp() override {
        pki::AuthorityOptions options;
        options.organization = "Essai";
        pki::init_authority(ca(), kPass, options);
    }

    std::filesystem::path ca() const { return dir_.path() / "ac"; }

    // gen-csr → ca sign → pki install → activate, pour une instance.
    void provision(const std::filesystem::path& pki_root, Role role, const std::string& subject,
                   const std::vector<std::string>& sans, bool renew = false) {
        const auto csr = pki::generate_csr(pki_root, subject, {});
        pki::SignRequest request;
        request.role = role;
        request.csr_pem = read(csr.csr);
        request.sans = sans_of(sans);
        request.renew = renew;
        const auto issued = pki::sign_request(ca(), kPass, request);
        const auto bundle = dir_.path() / ("kit-" + csr.generation + (role == Role::server ? "-s" : "-c"));
        pki::write_bundle(bundle, issued);
        pki::InstallFiles files;
        files.from = bundle;
        const pki::Requirements req{role, true, true};
        const auto result = pki::install(pki_root, std::nullopt, files, req);
        ASSERT_EQ(result.generation, csr.generation);
        for (const auto& e : result.check.errors) ADD_FAILURE() << e.path << " : " << e.message;
        ASSERT_TRUE(result.check.generation);
        pki::activate(pki_root, result.generation);
    }

    TempDir dir_;
};

}  // namespace

TEST_F(CaTest, InitCreatesHierarchyWithEncryptedKeys) {
    for (const char* f : {"root.key.pem", "servers.key.pem", "clients.key.pem"}) {
        const auto pem = read(ca() / f);
        EXPECT_NE(pem.find("BEGIN ENCRYPTED PRIVATE KEY"), std::string::npos) << f;
        tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
        EXPECT_FALSE(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast<char*>("mauvaise"))) << f;
        tls::take_openssl_errors();
#ifndef _WIN32
        struct stat st {};
        ASSERT_EQ(::stat((ca() / f).c_str(), &st), 0);
        EXPECT_EQ(st.st_mode & 0777, 0600u) << f;
#endif
    }
    const auto root = cert_of(read(ca() / "root.cert.pem"));
    const auto servers = cert_of(read(ca() / "servers.cert.pem"));
    ASSERT_TRUE(root && servers);
    EXPECT_EQ(tls::subject_of(root.get()), "CN=Essai AC Racine,O=Essai");
    EXPECT_EQ(X509_check_issued(root.get(), servers.get()), X509_V_OK);
    EXPECT_EQ(X509_get_pathlen(servers.get()), 0);
    EXPECT_TRUE(X509_get_extended_key_usage(servers.get()) & XKU_SSL_SERVER);
    EXPECT_EQ(EVP_PKEY_get_bits(X509_get0_pubkey(root.get())), 384);
    // Une seconde initialisation n'écrase rien.
    EXPECT_THROW(pki::init_authority(ca(), kPass, {}), std::runtime_error);
    EXPECT_THROW(pki::init_authority(dir_.path() / "autre", "court", {}), std::runtime_error);
}

TEST_F(CaTest, ProvisionedPkiCarriesAnMtlsChain) {
    const auto server_pki = dir_.path() / "serveur";
    const auto client_pki = dir_.path() / "client";
    provision(server_pki, Role::server, "CN=relay.essai,O=Essai", {"relay.essai", "127.0.0.1"});
    provision(client_pki, Role::client, "CN=agence.essai,O=Essai", {});

    std::ofstream(dir_.path() / "wl.yaml") << "peers:\n  - { name: agence, ip: 127.0.0.1, ports: [mtls], "
                                              "subject: \"CN=agence.essai,O=Essai\" }\n";
    EchoServer echo;
    Config s;
    s.mode = Mode::server;
    s.ports[PortKind::mtls].listen = Endpoint{"127.0.0.1", 0};
    s.destination = Destination{Endpoint{"127.0.0.1", echo.port()}};
    s.credentials = Credentials{server_pki.string()};
    s.whitelist = WhitelistRef{(dir_.path() / "wl.yaml").string()};
    RunningService server(std::move(s));
    Config c;
    c.mode = Mode::client;
    c.ports[PortKind::mtls] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", server.port(PortKind::mtls)},
                                         "relay.essai"};
    c.credentials = Credentials{client_pki.string()};
    RunningService client(std::move(c));

    TestClient app(client.port(PortKind::mtls));
    std::string sent;
    const auto received = exchange(app, 256 * 1024, 3, &sent);
    EXPECT_EQ(sha256(received), sha256(sent));
}

TEST_F(CaTest, GenCsrCreatesNextGenerationWithPrivateKey) {
    const auto root = dir_.path() / "pki";
    const auto first = pki::generate_csr(root, "CN=a.essai", sans_of({"a.essai"}));
    EXPECT_EQ(first.generation, "v1");
    EXPECT_EQ(pki::pending_generation(root), "v1");
    const auto second = pki::generate_csr(root, "CN=a.essai", {});
    EXPECT_EQ(second.generation, "v2");
    EXPECT_EQ(pki::next_generation_name(root), "v3");
    EXPECT_FALSE(std::filesystem::exists(root / "current"));  // rien n'est activé
#ifndef _WIN32
    struct stat st {};
    ASSERT_EQ(::stat((root / "v1" / "key.pem").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
#endif
    EXPECT_THROW(pki::generate_csr(root, "O=sans cn", {}), std::runtime_error);
    EXPECT_THROW(pki::generate_csr(root, "pas un DN", {}), std::runtime_error);
}

TEST_F(CaTest, SignAppliesCaPolicyAndIgnoresRequestedExtensions) {
    pki::SignRequest request;
    request.role = Role::server;
    // La demande réclame des droits d'AC et un usage client : ignorés.
    request.csr_pem = custom_csr("EC", "P-256", "ambitieux.essai",
                                 {{NID_basic_constraints, "critical,CA:TRUE"},
                                  {NID_ext_key_usage, "clientAuth,codeSigning"},
                                  {NID_subject_alt_name, "DNS:autre.exemple"}});
    request.sans = sans_of({"dns:ambitieux.essai"});
    const auto issued = pki::sign_request(ca(), kPass, request);
    EXPECT_EQ(issued.ignored_extensions,
              (std::vector<std::string>{"basicConstraints", "extendedKeyUsage", "subjectAltName"}));

    const auto cert = cert_of(issued.cert_pem);
    ASSERT_TRUE(cert);
    EXPECT_EQ(X509_check_ca(cert.get()), 0);
    EXPECT_EQ(X509_get_extended_key_usage(cert.get()), static_cast<std::uint32_t>(XKU_SSL_SERVER));
    EXPECT_EQ(X509_check_host(cert.get(), "ambitieux.essai", 0, 0, nullptr), 1);
    EXPECT_NE(X509_check_host(cert.get(), "autre.exemple", 0, 0, nullptr), 1);
    // Chaîne vérifiée par OpenSSL : racine → AC Serveurs → certificat.
    tls::X509StorePtr store(X509_STORE_new());
    X509_STORE_add_cert(store.get(), cert_of(issued.roots_pem).get());
    auto chain_cert = cert_of(issued.chain_pem);
    STACK_OF(X509)* untrusted = sk_X509_new_null();
    sk_X509_push(untrusted, chain_cert.get());
    tls::X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    X509_STORE_CTX_init(ctx.get(), store.get(), cert.get(), untrusted);
    X509_STORE_CTX_set_purpose(ctx.get(), X509_PURPOSE_SSL_SERVER);
    EXPECT_EQ(X509_verify_cert(ctx.get()), 1) << X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()));
    sk_X509_free(untrusted);
    // Fin de validité : un an par défaut.
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].serial, issued.serial);
    EXPECT_EQ(entries[0].status, "valide");
    EXPECT_EQ(entries[0].subject, "CN=ambitieux.essai");
}

TEST_F(CaTest, SignRefusesNonConformingRequests) {
    pki::SignRequest request;
    request.role = Role::client;
    auto refused = [&](const std::string& fragment) {
        try {
            pki::sign_request(ca(), kPass, request);
            ADD_FAILURE() << "demande acceptée, refus attendu : " << fragment;
        } catch (const std::runtime_error& e) {
            EXPECT_NE(std::string(e.what()).find(fragment), std::string::npos) << e.what();
        }
    };
    request.csr_pem = custom_csr("RSA", nullptr, "rsa.essai");
    refused("P-256");
    request.csr_pem = custom_csr("EC", "P-384", "p384.essai");
    refused("P-256");
    request.csr_pem = "pas une demande";
    refused("illisible");

    // Signature de la demande altérée.
    auto tampered = custom_csr("EC", "P-256", "altere.essai");
    tampered[tampered.size() / 2] = tampered[tampered.size() / 2] == 'A' ? 'B' : 'A';
    request.csr_pem = tampered;
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);

    request.csr_pem = custom_csr("EC", "P-256", "serveur.essai");
    request.role = Role::server;
    refused("SAN");  // serveur sans SAN

    request.role = Role::client;
    try {
        pki::sign_request(ca(), "mauvaise phrase", request);
        ADD_FAILURE() << "mauvaise phrase de passe acceptée";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("phrase de passe"), std::string::npos) << e.what();
    }
    EXPECT_TRUE(pki::list_issued(ca()).empty());  // aucun certificat émis
}

TEST_F(CaTest, SubjectIsAttributedOnceUnlessRenewed) {
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "agence.essai");
    const auto first = pki::sign_request(ca(), kPass, request);

    request.csr_pem = custom_csr("EC", "P-256", "agence.essai");  // autre clé, même sujet
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);

    request.renew = true;
    const auto second = pki::sign_request(ca(), kPass, request);
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].serial, first.serial);
    EXPECT_EQ(entries[0].status, "remplacé");
    EXPECT_EQ(entries[1].serial, second.serial);
    EXPECT_EQ(entries[1].status, "valide");

    // Renouvellement d'un sujet inconnu, ou sous un autre rôle : refusé.
    request.csr_pem = custom_csr("EC", "P-256", "inconnu.essai");
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);
    request.role = Role::server;
    request.sans = sans_of({"agence.essai"});
    request.csr_pem = custom_csr("EC", "P-256", "agence.essai");
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);
}

TEST_F(CaTest, RenewalRotatesKeyAndKeepsTrustFiles) {
    const auto root = dir_.path() / "serveur";
    provision(root, Role::server, "CN=relay.essai,O=Essai", {"relay.essai"});
    const auto key_v1 = read(root / "v1" / "key.pem");
    // Renouvellement : nouvelle clé dans v2 ; les fichiers de confiance sont repris de v1.
    const auto csr = pki::generate_csr(root, "CN=relay.essai,O=Essai", {});
    pki::SignRequest request;
    request.role = Role::server;
    request.csr_pem = read(csr.csr);
    request.sans = sans_of({"relay.essai"});
    request.renew = true;
    const auto issued = pki::sign_request(ca(), kPass, request);
    std::ofstream(dir_.path() / "cert.pem") << issued.cert_pem;
    std::ofstream(dir_.path() / "chain.pem") << issued.chain_pem;
    pki::InstallFiles files;
    files.cert = dir_.path() / "cert.pem";
    files.chain = dir_.path() / "chain.pem";
    const auto result = pki::install(root, std::nullopt, files, {Role::server, true, true});
    EXPECT_EQ(result.generation, "v2");
    for (const auto& e : result.check.errors) ADD_FAILURE() << e.path << " : " << e.message;
    EXPECT_TRUE(result.check.generation);  // garde-fou de rotation compris
    EXPECT_NE(read(root / "v2" / "key.pem"), key_v1);
    EXPECT_EQ(read(root / "v2" / "trust-roots.pem"), read(root / "v1" / "trust-roots.pem"));
    // Une génération complète ne se réinstalle pas.
    EXPECT_THROW(pki::install(root, std::string("v2"), files, {Role::server, true, true}), std::runtime_error);
}

TEST_F(CaTest, InstallRejectsCertificateForAnotherKey) {
    const auto root = dir_.path() / "client";
    pki::generate_csr(root, "CN=agence.essai", {});
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "agence.essai");  // autre clé que celle de v1
    const auto issued = pki::sign_request(ca(), kPass, request);
    const auto kit = dir_.path() / "kit";
    pki::write_bundle(kit, issued);
    pki::InstallFiles files;
    files.from = kit;
    const auto result = pki::install(root, std::nullopt, files, {Role::client, true, true});
    EXPECT_FALSE(result.check.generation);
    bool mismatch = false;
    for (const auto& e : result.check.errors) mismatch |= e.message.find("ne correspond pas") != std::string::npos;
    EXPECT_TRUE(mismatch);
}

TEST(SubjectAltNames, ParsesTypedAndBareValues) {
    std::string error;
    const auto sans = pki::parse_sans({"dns:relay.essai,ip:10.0.0.1", "::1", "agence.essai"}, error);
    ASSERT_TRUE(sans) << error;
    EXPECT_EQ(sans->dns, (std::vector<std::string>{"relay.essai", "agence.essai"}));
    EXPECT_EQ(sans->ip, (std::vector<std::string>{"10.0.0.1", "::1"}));
    EXPECT_EQ(sans->to_openssl(), "DNS:relay.essai,DNS:agence.essai,IP:10.0.0.1,IP:::1");
    EXPECT_FALSE(pki::parse_sans({"ip:relay.essai"}, error));
    EXPECT_FALSE(pki::parse_sans({"nom invalide!"}, error));
}

namespace {

using CrlPtr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;

std::vector<CrlPtr> crls_of(const std::string& pem) {
    std::vector<CrlPtr> out;
    tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    while (X509_CRL* crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) out.emplace_back(crl, X509_CRL_free);
    tls::take_openssl_errors();
    return out;
}

std::string serial_hex(const ASN1_INTEGER* serial) {
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* hex = BN_bn2hex(bn);
    std::string out(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    return out;
}

}  // namespace

TEST_F(CaTest, RevocationIsPublishedInSignedCrls) {
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "perdu.essai");
    const auto lost = pki::sign_request(ca(), kPass, request);
    request.csr_pem = custom_csr("EC", "P-256", "garde.essai");
    const auto kept = pki::sign_request(ca(), kPass, request);

    // Série en minuscules acceptée ; double révocation et série inconnue refusées.
    std::string lower = lost.serial;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const auto entry = pki::revoke_certificate(ca(), lower, pki::RevocationReason::key_compromise);
    EXPECT_EQ(entry.status, "révoqué");
    EXPECT_EQ(entry.reason, "keyCompromise");
    EXPECT_THROW(pki::revoke_certificate(ca(), lost.serial, pki::RevocationReason::unspecified), std::runtime_error);
    EXPECT_THROW(pki::revoke_certificate(ca(), "ABCDEF", pki::RevocationReason::unspecified), std::runtime_error);
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].status, "révoqué");
    EXPECT_FALSE(entries[0].revoked_at.empty());
    EXPECT_EQ(entries[1].status, "valide");

    EXPECT_THROW(pki::publish_crl(ca(), "mauvaise phrase de passe", 30), std::runtime_error);
    const auto crl = pki::publish_crl(ca(), kPass, 30);
    EXPECT_EQ(crl.number, 1u);
    EXPECT_EQ(crl.revoked, 1u);
    EXPECT_EQ(read(ca() / "crl.pem"), crl.pem);
    const auto list = crls_of(crl.pem);
    ASSERT_EQ(list.size(), 2u);  // AC Serveurs puis AC Clients

    const auto servers = cert_of(read(ca() / "servers.cert.pem"));
    const auto clients = cert_of(read(ca() / "clients.cert.pem"));
    EXPECT_EQ(X509_CRL_verify(list[0].get(), X509_get0_pubkey(servers.get())), 1);
    EXPECT_EQ(X509_CRL_verify(list[1].get(), X509_get0_pubkey(clients.get())), 1);
    EXPECT_LE(sk_X509_REVOKED_num(X509_CRL_get_REVOKED(list[0].get())), 0);  // liste absente : -1
    STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(list[1].get());
    ASSERT_EQ(sk_X509_REVOKED_num(revoked), 1);
    X509_REVOKED* r = sk_X509_REVOKED_value(revoked, 0);
    EXPECT_EQ(serial_hex(X509_REVOKED_get0_serialNumber(r)), lost.serial);
    auto* reason = static_cast<ASN1_ENUMERATED*>(X509_REVOKED_get_ext_d2i(r, NID_crl_reason, nullptr, nullptr));
    ASSERT_TRUE(reason);
    EXPECT_EQ(ASN1_ENUMERATED_get(reason), CRL_REASON_KEY_COMPROMISE);
    ASN1_ENUMERATED_free(reason);
    // Le certificat révoqué est reconnu par OpenSSL ; l'autre non.
    X509_REVOKED* found = nullptr;
    EXPECT_EQ(X509_CRL_get0_by_cert(list[1].get(), &found, cert_of(lost.cert_pem).get()), 1);
    EXPECT_EQ(X509_CRL_get0_by_cert(list[1].get(), &found, cert_of(kept.cert_pem).get()), 0);

    // Numérotation croissante.
    EXPECT_EQ(pki::publish_crl(ca(), kPass, 7).number, 2u);
    EXPECT_THROW(pki::publish_crl(ca(), kPass, 0), std::runtime_error);

    // Après révocation, le sujet peut recevoir un nouveau certificat sans --renew.
    request.csr_pem = custom_csr("EC", "P-256", "perdu.essai");
    EXPECT_NO_THROW(pki::sign_request(ca(), kPass, request));
}

TEST_F(CaTest, AuditLogRecordsOperationsAndDetectsTampering) {
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "audit.essai");
    const auto issued = pki::sign_request(ca(), kPass, request);
    pki::revoke_certificate(ca(), issued.serial, pki::RevocationReason::superseded);
    pki::publish_crl(ca(), kPass, 30);

    auto log = pki::read_audit(ca());
    EXPECT_FALSE(log.broken_line) << log.problem;
    ASSERT_EQ(log.entries.size(), 4u);
    EXPECT_EQ(log.entries[0].operation, "init");
    EXPECT_EQ(log.entries[1].operation, "sign");
    EXPECT_NE(log.entries[1].details.find(issued.serial), std::string::npos);
    EXPECT_EQ(log.entries[2].operation, "revoke");
    EXPECT_EQ(log.entries[3].operation, "crl");
    EXPECT_EQ(log.entries[0].operator_name, pki::current_operator());

    // Une ligne modifiée rompt la chaîne à partir de cette ligne.
    auto text = read(ca() / "audit.log");
    const auto pos = text.find("revoke");
    text.replace(pos, 6, "revok3");
    { std::ofstream(ca() / "audit.log", std::ios::binary | std::ios::trunc) << text; }
    log = pki::read_audit(ca());
    ASSERT_TRUE(log.broken_line);
    EXPECT_EQ(*log.broken_line, 3u);
    EXPECT_EQ(log.entries.size(), 2u);

    // Une ligne supprimée aussi.
    auto lines = read(ca() / "audit.log");
    lines.erase(0, lines.find('\n') + 1);
    { std::ofstream(ca() / "audit.log", std::ios::binary | std::ios::trunc) << lines; }
    log = pki::read_audit(ca());
    ASSERT_TRUE(log.broken_line);
    EXPECT_EQ(*log.broken_line, 1u);

    // Champs nettoyés : une tabulation ou une fin de ligne ne casse pas le format.
    std::filesystem::remove(ca() / "audit.log");
    pki::append_audit(ca(), "test", "a\tb\nc");
    log = pki::read_audit(ca());
    ASSERT_FALSE(log.broken_line) << log.problem;
    ASSERT_EQ(log.entries.size(), 1u);
    EXPECT_EQ(log.entries[0].details, "a b c");
}

TEST_F(CaTest, IndexWithoutRevocationColumnsIsStillRead) {
    // Inventaire écrit par la livraison 1 : cinq colonnes.
    { std::ofstream(ca() / "index.tsv", std::ios::binary | std::ios::trunc)
          << "# série\trôle\tétat\tfin de validité\tsujet\n"
          << "0A1B\tclient\tvalide\t2099-01-01 00:00:00Z\tCN=ancien,O=Essai\n"; }
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].subject, "CN=ancien,O=Essai");
    EXPECT_TRUE(entries[0].revoked_at.empty());
    const auto revoked = pki::revoke_certificate(ca(), "0a1b", pki::RevocationReason::cessation_of_operation);
    EXPECT_EQ(revoked.subject, "CN=ancien,O=Essai");
    EXPECT_EQ(pki::list_issued(ca())[0].reason, "cessationOfOperation");
    EXPECT_EQ(pki::publish_crl(ca(), kPass, 30).revoked, 1u);
}

TEST_F(CaTest, PublishedCrlIsAcceptedByInstancesOfBothRoles) {
    const auto server_root = dir_.path() / "serveur";
    const auto client_root = dir_.path() / "client";
    provision(server_root, Role::server, "CN=relay.essai,O=Essai", {"relay.essai"});
    provision(client_root, Role::client, "CN=agence.essai,O=Essai", {});
    const auto client_cert = cert_of(read(client_root / "v1" / "cert.pem"));
    const auto server_cert = cert_of(read(server_root / "v1" / "cert.pem"));
    const auto serial = pki::list_issued(ca()).back().serial;  // certificat client
    pki::revoke_certificate(ca(), serial, pki::RevocationReason::key_compromise);
    const auto crl = pki::publish_crl(ca(), kPass, 30);
    std::ofstream(dir_.path() / "crl.pem", std::ios::binary) << crl.pem;

    const pki::Requirements server_req{Role::server, true, true};
    const auto server_gen = pki::load_current_generation(server_root, server_req);
    ASSERT_TRUE(server_gen.generation);
    const auto on_server = pki::load_revocations(dir_.path() / "crl.pem", *server_gen.generation);
    ASSERT_TRUE(on_server.list);
    EXPECT_TRUE(on_server.warnings.empty()) << on_server.warnings.front().message;
    EXPECT_TRUE(on_server.list->is_revoked(client_cert.get()));

    const pki::Requirements client_req{Role::client, true, true};
    const auto client_gen = pki::load_current_generation(client_root, client_req);
    ASSERT_TRUE(client_gen.generation);
    const auto on_client = pki::load_revocations(dir_.path() / "crl.pem", *client_gen.generation);
    ASSERT_TRUE(on_client.list);
    EXPECT_FALSE(on_client.list->is_revoked(server_cert.get()));
    // Le client apprend que son propre certificat est révoqué.
    ASSERT_FALSE(on_client.warnings.empty());
    EXPECT_NE(on_client.warnings.front().message.find("cette instance"), std::string::npos);
}
