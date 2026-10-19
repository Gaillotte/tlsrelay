// Command-line PKI (phase 7, SPEC §7.6): mini-CA, signing requests,
// installation of a generation. The PKI produced by the mini-CA is then
// used for a real mTLS chain.

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

const std::string kPass = "test passphrase 123";

std::string read(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

tls::X509Ptr cert_of(const std::string& pem) {
    tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    return tls::X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// Hand-built request (any key and extensions) to test the CA policy.
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
        options.organization = "Test";
        pki::init_authority(ca(), kPass, options);
    }

    std::filesystem::path ca() const { return dir_.path() / "ac"; }

    // gen-csr → ca sign → pki install → activate, for one instance.
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
        for (const auto& e : result.check.errors) ADD_FAILURE() << e.path << ": " << e.message;
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
        EXPECT_FALSE(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, const_cast<char*>("wrong"))) << f;
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
    EXPECT_EQ(tls::subject_of(root.get()), "CN=Test Root CA,O=Test");
    EXPECT_EQ(X509_check_issued(root.get(), servers.get()), X509_V_OK);
    EXPECT_EQ(X509_get_pathlen(servers.get()), 0);
    EXPECT_TRUE(X509_get_extended_key_usage(servers.get()) & XKU_SSL_SERVER);
    EXPECT_EQ(EVP_PKEY_get_bits(X509_get0_pubkey(root.get())), 384);
    // A second initialization overwrites nothing.
    EXPECT_THROW(pki::init_authority(ca(), kPass, {}), std::runtime_error);
    EXPECT_THROW(pki::init_authority(dir_.path() / "other", "short", {}), std::runtime_error);
}

TEST_F(CaTest, ProvisionedPkiCarriesAnMtlsChain) {
    const auto server_pki = dir_.path() / "server";
    const auto client_pki = dir_.path() / "client";
    provision(server_pki, Role::server, "CN=relay.test,O=Test", {"relay.test", "127.0.0.1"});
    provision(client_pki, Role::client, "CN=branch.test,O=Test", {});

    std::ofstream(dir_.path() / "wl.yaml") << "peers:\n  - { name: branch, ip: 127.0.0.1, ports: [mtls], "
                                              "subject: \"CN=branch.test,O=Test\" }\n";
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
                                         "relay.test"};
    c.credentials = Credentials{client_pki.string()};
    RunningService client(std::move(c));

    TestClient app(client.port(PortKind::mtls));
    std::string sent;
    const auto received = exchange(app, 256 * 1024, 3, &sent);
    EXPECT_EQ(sha256(received), sha256(sent));
}

TEST_F(CaTest, GenCsrCreatesNextGenerationWithPrivateKey) {
    const auto root = dir_.path() / "pki";
    const auto first = pki::generate_csr(root, "CN=a.test", sans_of({"a.test"}));
    EXPECT_EQ(first.generation, "v1");
    EXPECT_EQ(pki::pending_generation(root), "v1");
    const auto second = pki::generate_csr(root, "CN=a.test", {});
    EXPECT_EQ(second.generation, "v2");
    EXPECT_EQ(pki::next_generation_name(root), "v3");
    EXPECT_FALSE(std::filesystem::exists(root / "current"));  // nothing is activated
#ifndef _WIN32
    struct stat st {};
    ASSERT_EQ(::stat((root / "v1" / "key.pem").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
#endif
    EXPECT_THROW(pki::generate_csr(root, "O=no cn", {}), std::runtime_error);
    EXPECT_THROW(pki::generate_csr(root, "not a DN", {}), std::runtime_error);
}

TEST_F(CaTest, SignAppliesCaPolicyAndIgnoresRequestedExtensions) {
    pki::SignRequest request;
    request.role = Role::server;
    // The request asks for CA rights and client usage: ignored.
    request.csr_pem = custom_csr("EC", "P-256", "ambitious.test",
                                 {{NID_basic_constraints, "critical,CA:TRUE"},
                                  {NID_ext_key_usage, "clientAuth,codeSigning"},
                                  {NID_subject_alt_name, "DNS:other.example"}});
    request.sans = sans_of({"dns:ambitious.test"});
    const auto issued = pki::sign_request(ca(), kPass, request);
    EXPECT_EQ(issued.ignored_extensions,
              (std::vector<std::string>{"basicConstraints", "extendedKeyUsage", "subjectAltName"}));

    const auto cert = cert_of(issued.cert_pem);
    ASSERT_TRUE(cert);
    EXPECT_EQ(X509_check_ca(cert.get()), 0);
    EXPECT_EQ(X509_get_extended_key_usage(cert.get()), static_cast<std::uint32_t>(XKU_SSL_SERVER));
    EXPECT_EQ(X509_check_host(cert.get(), "ambitious.test", 0, 0, nullptr), 1);
    EXPECT_NE(X509_check_host(cert.get(), "other.example", 0, 0, nullptr), 1);
    // Chain verified by OpenSSL: root → Servers CA → certificate.
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
    // Expiry: one year by default.
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].serial, issued.serial);
    EXPECT_EQ(entries[0].status, "valid");
    EXPECT_EQ(entries[0].subject, "CN=ambitious.test");
}

TEST_F(CaTest, SignRefusesNonConformingRequests) {
    pki::SignRequest request;
    request.role = Role::client;
    auto refused = [&](const std::string& fragment) {
        try {
            pki::sign_request(ca(), kPass, request);
            ADD_FAILURE() << "request accepted, refusal expected: " << fragment;
        } catch (const std::runtime_error& e) {
            EXPECT_NE(std::string(e.what()).find(fragment), std::string::npos) << e.what();
        }
    };
    request.csr_pem = custom_csr("RSA", nullptr, "rsa.test");
    refused("P-256");
    request.csr_pem = custom_csr("EC", "P-384", "p384.test");
    refused("P-256");
    request.csr_pem = "not a request";
    refused("unreadable");

    // Tampered request signature.
    auto tampered = custom_csr("EC", "P-256", "tampered.test");
    tampered[tampered.size() / 2] = tampered[tampered.size() / 2] == 'A' ? 'B' : 'A';
    request.csr_pem = tampered;
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);

    request.csr_pem = custom_csr("EC", "P-256", "server.test");
    request.role = Role::server;
    refused("SAN");  // server without SAN

    request.role = Role::client;
    try {
        pki::sign_request(ca(), "wrong passphrase", request);
        ADD_FAILURE() << "wrong passphrase accepted";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("passphrase"), std::string::npos) << e.what();
    }
    EXPECT_TRUE(pki::list_issued(ca()).empty());  // no certificate issued
}

TEST_F(CaTest, SubjectIsAttributedOnceUnlessRenewed) {
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "branch.test");
    const auto first = pki::sign_request(ca(), kPass, request);

    request.csr_pem = custom_csr("EC", "P-256", "branch.test");  // another key, same subject
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);

    request.renew = true;
    const auto second = pki::sign_request(ca(), kPass, request);
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].serial, first.serial);
    EXPECT_EQ(entries[0].status, "replaced");
    EXPECT_EQ(entries[1].serial, second.serial);
    EXPECT_EQ(entries[1].status, "valid");

    // Renewal of an unknown subject, or under another role: refused.
    request.csr_pem = custom_csr("EC", "P-256", "unknown.test");
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);
    request.role = Role::server;
    request.sans = sans_of({"branch.test"});
    request.csr_pem = custom_csr("EC", "P-256", "branch.test");
    EXPECT_THROW(pki::sign_request(ca(), kPass, request), std::runtime_error);
}

TEST_F(CaTest, RenewalRotatesKeyAndKeepsTrustFiles) {
    const auto root = dir_.path() / "server";
    provision(root, Role::server, "CN=relay.test,O=Test", {"relay.test"});
    const auto key_v1 = read(root / "v1" / "key.pem");
    // Renewal: new key in v2; the trust files are taken from v1.
    const auto csr = pki::generate_csr(root, "CN=relay.test,O=Test", {});
    pki::SignRequest request;
    request.role = Role::server;
    request.csr_pem = read(csr.csr);
    request.sans = sans_of({"relay.test"});
    request.renew = true;
    const auto issued = pki::sign_request(ca(), kPass, request);
    std::ofstream(dir_.path() / "cert.pem") << issued.cert_pem;
    std::ofstream(dir_.path() / "chain.pem") << issued.chain_pem;
    pki::InstallFiles files;
    files.cert = dir_.path() / "cert.pem";
    files.chain = dir_.path() / "chain.pem";
    const auto result = pki::install(root, std::nullopt, files, {Role::server, true, true});
    EXPECT_EQ(result.generation, "v2");
    for (const auto& e : result.check.errors) ADD_FAILURE() << e.path << ": " << e.message;
    EXPECT_TRUE(result.check.generation);  // rotation safeguard included
    EXPECT_NE(read(root / "v2" / "key.pem"), key_v1);
    EXPECT_EQ(read(root / "v2" / "trust-roots.pem"), read(root / "v1" / "trust-roots.pem"));
    // A complete generation cannot be reinstalled.
    EXPECT_THROW(pki::install(root, std::string("v2"), files, {Role::server, true, true}), std::runtime_error);
}

TEST_F(CaTest, InstallRejectsCertificateForAnotherKey) {
    const auto root = dir_.path() / "client";
    pki::generate_csr(root, "CN=branch.test", {});
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "branch.test");  // another key than v1's
    const auto issued = pki::sign_request(ca(), kPass, request);
    const auto kit = dir_.path() / "kit";
    pki::write_bundle(kit, issued);
    pki::InstallFiles files;
    files.from = kit;
    const auto result = pki::install(root, std::nullopt, files, {Role::client, true, true});
    EXPECT_FALSE(result.check.generation);
    bool mismatch = false;
    for (const auto& e : result.check.errors) mismatch |= e.message.find("does not match") != std::string::npos;
    EXPECT_TRUE(mismatch);
}

TEST(SubjectAltNames, ParsesTypedAndBareValues) {
    std::string error;
    const auto sans = pki::parse_sans({"dns:relay.test,ip:10.0.0.1", "::1", "branch.test"}, error);
    ASSERT_TRUE(sans) << error;
    EXPECT_EQ(sans->dns, (std::vector<std::string>{"relay.test", "branch.test"}));
    EXPECT_EQ(sans->ip, (std::vector<std::string>{"10.0.0.1", "::1"}));
    EXPECT_EQ(sans->to_openssl(), "DNS:relay.test,DNS:branch.test,IP:10.0.0.1,IP:::1");
    EXPECT_FALSE(pki::parse_sans({"ip:relay.test"}, error));
    EXPECT_FALSE(pki::parse_sans({"invalid name!"}, error));
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
    request.csr_pem = custom_csr("EC", "P-256", "lost.test");
    const auto lost = pki::sign_request(ca(), kPass, request);
    request.csr_pem = custom_csr("EC", "P-256", "kept.test");
    const auto kept = pki::sign_request(ca(), kPass, request);

    // Lowercase serial accepted; double revocation and unknown serial refused.
    std::string lower = lost.serial;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const auto entry = pki::revoke_certificate(ca(), lower, pki::RevocationReason::key_compromise);
    EXPECT_EQ(entry.status, "revoked");
    EXPECT_EQ(entry.reason, "keyCompromise");
    EXPECT_THROW(pki::revoke_certificate(ca(), lost.serial, pki::RevocationReason::unspecified), std::runtime_error);
    EXPECT_THROW(pki::revoke_certificate(ca(), "ABCDEF", pki::RevocationReason::unspecified), std::runtime_error);
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].status, "revoked");
    EXPECT_FALSE(entries[0].revoked_at.empty());
    EXPECT_EQ(entries[1].status, "valid");

    EXPECT_THROW(pki::publish_crl(ca(), "wrong passphrase", 30), std::runtime_error);
    const auto crl = pki::publish_crl(ca(), kPass, 30);
    EXPECT_EQ(crl.number, 1u);
    EXPECT_EQ(crl.revoked, 1u);
    EXPECT_EQ(read(ca() / "crl.pem"), crl.pem);
    const auto list = crls_of(crl.pem);
    ASSERT_EQ(list.size(), 2u);  // Servers CA, then Clients CA

    const auto servers = cert_of(read(ca() / "servers.cert.pem"));
    const auto clients = cert_of(read(ca() / "clients.cert.pem"));
    EXPECT_EQ(X509_CRL_verify(list[0].get(), X509_get0_pubkey(servers.get())), 1);
    EXPECT_EQ(X509_CRL_verify(list[1].get(), X509_get0_pubkey(clients.get())), 1);
    EXPECT_LE(sk_X509_REVOKED_num(X509_CRL_get_REVOKED(list[0].get())), 0);  // list absent: -1
    STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(list[1].get());
    ASSERT_EQ(sk_X509_REVOKED_num(revoked), 1);
    X509_REVOKED* r = sk_X509_REVOKED_value(revoked, 0);
    EXPECT_EQ(serial_hex(X509_REVOKED_get0_serialNumber(r)), lost.serial);
    auto* reason = static_cast<ASN1_ENUMERATED*>(X509_REVOKED_get_ext_d2i(r, NID_crl_reason, nullptr, nullptr));
    ASSERT_TRUE(reason);
    EXPECT_EQ(ASN1_ENUMERATED_get(reason), CRL_REASON_KEY_COMPROMISE);
    ASN1_ENUMERATED_free(reason);
    // The revoked certificate is recognized by OpenSSL; the other is not.
    X509_REVOKED* found = nullptr;
    EXPECT_EQ(X509_CRL_get0_by_cert(list[1].get(), &found, cert_of(lost.cert_pem).get()), 1);
    EXPECT_EQ(X509_CRL_get0_by_cert(list[1].get(), &found, cert_of(kept.cert_pem).get()), 0);

    // Increasing numbering.
    EXPECT_EQ(pki::publish_crl(ca(), kPass, 7).number, 2u);
    EXPECT_THROW(pki::publish_crl(ca(), kPass, 0), std::runtime_error);

    // After revocation, the subject can receive a new certificate without --renew.
    request.csr_pem = custom_csr("EC", "P-256", "lost.test");
    EXPECT_NO_THROW(pki::sign_request(ca(), kPass, request));
}

TEST_F(CaTest, AuditLogRecordsOperationsAndDetectsTampering) {
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "audit.test");
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

    // A modified line breaks the chain from that line on.
    auto text = read(ca() / "audit.log");
    const auto pos = text.find("revoke");
    text.replace(pos, 6, "revok3");
    { std::ofstream(ca() / "audit.log", std::ios::binary | std::ios::trunc) << text; }
    log = pki::read_audit(ca());
    ASSERT_TRUE(log.broken_line);
    EXPECT_EQ(*log.broken_line, 3u);
    EXPECT_EQ(log.entries.size(), 2u);

    // So does a deleted line.
    auto lines = read(ca() / "audit.log");
    lines.erase(0, lines.find('\n') + 1);
    { std::ofstream(ca() / "audit.log", std::ios::binary | std::ios::trunc) << lines; }
    log = pki::read_audit(ca());
    ASSERT_TRUE(log.broken_line);
    EXPECT_EQ(*log.broken_line, 1u);

    // Cleaned fields: a tab or a line break does not break the format.
    std::filesystem::remove(ca() / "audit.log");
    pki::append_audit(ca(), "test", "a\tb\nc");
    log = pki::read_audit(ca());
    ASSERT_FALSE(log.broken_line) << log.problem;
    ASSERT_EQ(log.entries.size(), 1u);
    EXPECT_EQ(log.entries[0].details, "a b c");

    // CA older than release 1.1: no log yet, nothing tampered with.
    std::filesystem::remove(ca() / "audit.log");
    log = pki::read_audit(ca());
    EXPECT_TRUE(log.entries.empty());
    EXPECT_FALSE(log.broken_line);
    // Directory that is not a CA (typo): error, not an "intact" log.
    EXPECT_THROW(pki::read_audit(ca() / "missing"), std::runtime_error);
}

TEST_F(CaTest, IndexWithoutRevocationColumnsIsStillRead) {
    // Inventory written by release 1: five columns, French status values.
    { std::ofstream(ca() / "index.tsv", std::ios::binary | std::ios::trunc)
          << "# serial\trole\tstatus\tnot after\tsubject\n"
          << "0A1B\tclient\tvalide\t2099-01-01 00:00:00Z\tCN=old,O=Test\n"; }
    const auto entries = pki::list_issued(ca());
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0].subject, "CN=old,O=Test");
    EXPECT_EQ(entries[0].status, "valid");
    EXPECT_TRUE(entries[0].revoked_at.empty());
    const auto revoked = pki::revoke_certificate(ca(), "0a1b", pki::RevocationReason::cessation_of_operation);
    EXPECT_EQ(revoked.subject, "CN=old,O=Test");
    EXPECT_EQ(pki::list_issued(ca())[0].reason, "cessationOfOperation");
    EXPECT_EQ(pki::publish_crl(ca(), kPass, 30).revoked, 1u);
}

TEST_F(CaTest, PublishedCrlIsAcceptedByInstancesOfBothRoles) {
    const auto server_root = dir_.path() / "server";
    const auto client_root = dir_.path() / "client";
    provision(server_root, Role::server, "CN=relay.test,O=Test", {"relay.test"});
    provision(client_root, Role::client, "CN=branch.test,O=Test", {});
    const auto client_cert = cert_of(read(client_root / "v1" / "cert.pem"));
    const auto server_cert = cert_of(read(server_root / "v1" / "cert.pem"));
    const auto serial = pki::list_issued(ca()).back().serial;  // client certificate
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
    // The client learns that its own certificate is revoked.
    ASSERT_FALSE(on_client.warnings.empty());
    EXPECT_NE(on_client.warnings.front().message.find("this instance"), std::string::npos);
}

TEST_F(CaTest, DescribeAuthoritySummarizesCertificatesAndCrl) {
    pki::SignRequest request;
    request.role = Role::client;
    request.csr_pem = custom_csr("EC", "P-256", "a.test");
    const auto a = pki::sign_request(ca(), kPass, request);
    request.csr_pem = custom_csr("EC", "P-256", "b.test");
    pki::sign_request(ca(), kPass, request);
    auto info = pki::describe_authority(ca());
    EXPECT_EQ(info.root.subject, "CN=Test Root CA,O=Test");
    EXPECT_EQ(info.servers.subject, "CN=Test Servers CA,O=Test");
    EXPECT_EQ(info.root.fingerprint.size(), 32u * 3 - 1);
    EXPECT_EQ(info.issued, 2u);
    EXPECT_EQ(info.valid, 2u);
    EXPECT_EQ(info.crl_number, 0u);
    EXPECT_TRUE(info.crl_next_update.empty());
    pki::revoke_certificate(ca(), a.serial, pki::RevocationReason::unspecified);
    pki::publish_crl(ca(), kPass, 10);
    info = pki::describe_authority(ca());
    EXPECT_EQ(info.valid, 1u);
    EXPECT_EQ(info.revoked, 1u);
    EXPECT_EQ(info.crl_number, 1u);
    EXPECT_FALSE(info.crl_next_update.empty());
    EXPECT_FALSE(pki::is_past(info.crl_next_update));
    EXPECT_TRUE(pki::is_past("2000-01-01 00:00:00Z"));
    EXPECT_THROW(pki::describe_authority(dir_.path() / "absent"), std::runtime_error);
}

// Full root change with the files produced by write_root_transition:
// each step passes the rotation safeguard (SPEC §7.3) on a server and a client.
TEST_F(CaTest, RootTransitionFilesDriveTheThreeSteps) {
    const auto server_root = dir_.path() / "server";
    const auto client_root = dir_.path() / "client";
    provision(server_root, Role::server, "CN=relay.test,O=Test", {"relay.test"});
    provision(client_root, Role::client, "CN=branch.test,O=Test", {});
    const auto new_ca = dir_.path() / "ac2";
    pki::AuthorityOptions options;
    options.organization = "Test";
    pki::init_authority(new_ca, kPass, options);
    EXPECT_THROW(pki::write_root_transition(ca(), ca(), dir_.path() / "x"), std::runtime_error);
    const auto out = dir_.path() / "transition";
    pki::write_root_transition(ca(), new_ca, out);
    EXPECT_NE(read(out / "README.txt").find("Step 3"), std::string::npos);
    EXPECT_EQ(pki::read_audit(ca()).entries.back().operation, "root-transition");
    EXPECT_EQ(pki::read_audit(new_ca).entries.back().operation, "root-transition");

    struct Instance {
        std::filesystem::path root;
        Role role;
        std::string subject;
        std::vector<std::string> sans;
        std::string side;
    };
    const Instance instances[] = {{server_root, Role::server, "CN=relay.test,O=Test", {"relay.test"}, "server"},
                                  {client_root, Role::client, "CN=branch.test,O=Test", {}, "client"}};
    auto step = [&](const Instance& inst, const std::filesystem::path& authority, bool renew, bool transition_trust) {
        const auto csr = pki::generate_csr(inst.root, inst.subject, {});
        pki::SignRequest request;
        request.role = inst.role;
        request.csr_pem = read(csr.csr);
        request.sans = sans_of(inst.sans);
        request.renew = renew;
        const auto kit = dir_.path() / ("kit-" + inst.side + "-" + csr.generation);
        pki::write_bundle(kit, pki::sign_request(authority, kPass, request));
        pki::InstallFiles files;
        files.from = kit;
        if (transition_trust) {
            files.roots = out / inst.side / "trust-roots.pem";
            files.issuer = out / inst.side / "trust-issuer.pem";
        }
        const auto result = pki::install(inst.root, std::nullopt, files, pki::Requirements{inst.role, true, true});
        for (const auto& e : result.check.errors) ADD_FAILURE() << inst.side << " " << csr.generation << ": " << e.message;
        ASSERT_TRUE(result.check.generation);
        pki::activate(inst.root, result.generation);
    };
    for (const auto& inst : instances) step(inst, ca(), true, true);       // step 1: pre-trust
    for (const auto& inst : instances) step(inst, new_ca, false, true);   // step 2: switchover
    for (const auto& inst : instances) step(inst, new_ca, true, false);   // step 3: withdrawal
    const auto final_gen = pki::load_current_generation(server_root, pki::Requirements{Role::server, true, true});
    ASSERT_TRUE(final_gen.generation);
    EXPECT_EQ(final_gen.generation->trust_roots.size(), 1u);
    EXPECT_EQ(tls::subject_of(final_gen.generation->trust_roots.front().get()), "CN=Test Root CA,O=Test");
}
