// Chargement et contrôles d'une génération PKI (SPEC §7.2, §7.3).

#include "tlsrelay/pki/generation.hpp"

#include "support/test_pki.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>

using namespace tlsrelay;
using namespace testpki;
using pki::Requirements;
using pki::Role;

namespace {

const Requirements kServer{Role::server, true, false};
const Requirements kServerMtls{Role::server, true, true};
const Requirements kClient{Role::client, false, true};

bool has(const std::vector<Issue>& issues, const std::string& file, const std::string& fragment) {
    return std::any_of(issues.begin(), issues.end(), [&](const Issue& i) {
        return i.path.find(file) != std::string::npos && i.message.find(fragment) != std::string::npos;
    });
}

std::string dump(const pki::LoadResult& r) {
    std::string s;
    for (const auto& e : r.errors) s += "erreur " + e.path + " : " + e.message + "\n";
    for (const auto& w : r.warnings) s += "avertissement " + w.path + " : " + w.message + "\n";
    return s;
}

class PkiTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create()); }
    static void TearDownTestSuite() { delete h_; }

    pki::LoadResult load(const GenerationFiles& files, const Requirements& req) {
        write_generation(dir_.path(), "v1", files);
        return pki::load_current_generation(dir_.path(), req);
    }

    static Hierarchy* h_;
    TempDir dir_;
};
Hierarchy* PkiTest::h_ = nullptr;

}  // namespace

TEST_F(PkiTest, LoadsServerGeneration) {
    const auto r = load(server_files(*h_), kServerMtls);
    ASSERT_TRUE(r.generation) << dump(r);
    EXPECT_TRUE(r.warnings.empty()) << dump(r);
    EXPECT_EQ(r.generation->name, "v1");
    EXPECT_EQ(tls::subject_of(r.generation->cert.get()), "CN=relay.test,O=tlsrelay-test");
    ASSERT_EQ(r.generation->chain.size(), 1u);
    EXPECT_EQ(r.generation->trust_roots.size(), 1u);
}

TEST_F(PkiTest, LoadsClientGenerationWithTrustOnly) {
    GenerationFiles files;
    files.trust_roots = pem(h_->root.cert.get());
    files.trust_issuer = pem(h_->servers_ca.cert.get());
    const auto r = load(files, kClient);
    ASSERT_TRUE(r.generation) << dump(r);
    EXPECT_FALSE(r.generation->cert);
    EXPECT_EQ(r.generation->trust_issuers.size(), 1u);
}

TEST_F(PkiTest, RejectsMissingOrInvalidPointer) {
    auto r = pki::load_current_generation(dir_.path(), kServer);
    EXPECT_TRUE(has(r.errors, "current", "absent")) << dump(r);

    std::ofstream(dir_.path() / "current") << "../etc\n";
    r = pki::load_current_generation(dir_.path(), kServer);
    EXPECT_TRUE(has(r.errors, "current", "nom de génération invalide")) << dump(r);
}

TEST_F(PkiTest, ReportsEveryMissingFile) {
    const auto r = load(GenerationFiles{}, kServerMtls);
    EXPECT_FALSE(r.generation);
    for (const char* file : {"key.pem", "cert.pem", "chain.pem", "trust-roots.pem", "trust-issuer.pem"}) {
        EXPECT_TRUE(has(r.errors, file, "absent")) << file << "\n" << dump(r);
    }
}

TEST_F(PkiTest, RejectsKeyNotMatchingCertificate) {
    auto files = server_files(*h_);
    files.key = pem(h_->client.key.get());
    const auto r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "key.pem", "ne correspond pas")) << dump(r);
}

TEST_F(PkiTest, RejectsEncryptedKeyWithoutPrompting) {
    auto files = server_files(*h_);
    files.key = encrypted_pem(h_->server.key.get(), "secret");
    const auto r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "key.pem", "chiffrée")) << dump(r);
}

TEST_F(PkiTest, RejectsExpiredAndNotYetValidCertificates) {
    auto expired = make_certificate({.common_name = "relay.test", .usage = Usage::server,
                                     .not_before_offset = -7200, .not_after_offset = -3600}, &h_->servers_ca);
    auto files = server_files(*h_);
    files.key = pem(expired.key.get());
    files.cert = pem(expired.cert.get());
    auto r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "cert.pem", "expiré")) << dump(r);

    auto future = make_certificate({.common_name = "relay.test", .usage = Usage::server,
                                    .not_before_offset = 3600}, &h_->servers_ca);
    files.key = pem(future.key.get());
    files.cert = pem(future.cert.get());
    r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "cert.pem", "pas encore valide")) << dump(r);
}

TEST_F(PkiTest, WarnsWhenExpiryIsNear) {
    auto soon = make_certificate({.common_name = "relay.test", .usage = Usage::server,
                                  .not_after_offset = 10L * 24 * 3600}, &h_->servers_ca);
    auto files = server_files(*h_);
    files.key = pem(soon.key.get());
    files.cert = pem(soon.cert.get());
    const auto r = load(files, kServer);  // seuil par défaut : 30 jours
    ASSERT_TRUE(r.generation) << dump(r);
    EXPECT_TRUE(has(r.warnings, "cert.pem", "expirant")) << dump(r);
}

TEST_F(PkiTest, RejectsCertificateWithWrongUsageForRole) {
    // Certificat client présenté par un serveur.
    auto files = server_files(*h_);
    files.key = pem(h_->client.key.get());
    files.cert = pem(h_->client.cert.get());
    files.chain = pem(h_->clients_ca.cert.get());
    const auto r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "cert.pem", "usage incompatible")) << dump(r);
}

TEST_F(PkiTest, RejectsChainThatDidNotIssueCertificate) {
    auto files = server_files(*h_);
    files.chain = pem(h_->clients_ca.cert.get());
    const auto r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "chain.pem", "émetteur")) << dump(r);
}

TEST_F(PkiTest, RejectsChainNotAnchoredInTrustedRoots) {
    const auto other = Hierarchy::create("Autre");
    auto files = server_files(*h_);
    files.trust_roots = pem(other.root.cert.get());
    files.trust_issuer = pem(other.clients_ca.cert.get());
    const auto r = load(files, kServerMtls);
    EXPECT_TRUE(has(r.errors, "cert.pem", "chaîne invalide")) << dump(r);
}

TEST_F(PkiTest, RejectsTrustIssuerThatIsNotACa) {
    GenerationFiles files;
    files.trust_roots = pem(h_->root.cert.get());
    files.trust_issuer = pem(h_->server.cert.get());
    const auto r = load(files, kClient);
    EXPECT_TRUE(has(r.errors, "trust-issuer.pem", "n'est pas une AC")) << dump(r);
}

TEST_F(PkiTest, RejectsGarbageFiles) {
    auto files = server_files(*h_);
    files.cert = "pas un certificat";
    const auto r = load(files, kServer);
    EXPECT_TRUE(has(r.errors, "cert.pem", "aucun certificat")) << dump(r);
}

TEST(PkiRequirements, DependOnModeAndPorts) {
    Config c;
    c.ports[PortKind::plain] = {};
    EXPECT_FALSE(pki::requirements_for(c));

    c.mode = Mode::server;
    c.ports[PortKind::tls] = {};
    auto r = pki::requirements_for(c);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->role, Role::server);
    EXPECT_TRUE(r->identity);
    EXPECT_FALSE(r->trust);

    c.mode = Mode::client;
    r = pki::requirements_for(c);
    EXPECT_EQ(r->role, Role::client);
    EXPECT_FALSE(r->identity);
    EXPECT_TRUE(r->trust);

    c.ports[PortKind::mtls] = {};
    r = pki::requirements_for(c);
    EXPECT_TRUE(r->identity);
    EXPECT_TRUE(r->trust);
}

TEST_F(PkiTest, CheckCandidateAppliesRootGuard) {
    write_generation(dir_.path(), "v1", server_files(*h_));
    // v2 : nouvelle racine sans pré-confiance -> refusée.
    const auto other = Hierarchy::create("Autre");
    write_generation(dir_.path(), "v2", server_files(other), false);
    auto r = pki::check_candidate(dir_.path(), "v2", kServerMtls);
    EXPECT_FALSE(r.generation);
    EXPECT_TRUE(has(r.errors, "v2", "aucune racine de confiance commune")) << dump(r);

    // v3 : même racine, nouveau certificat -> acceptée.
    auto files = server_files(*h_);
    auto renewed = make_certificate({.common_name = "relay.test", .usage = Usage::server, .dns = {"relay.test"}},
                                    &h_->servers_ca);
    files.key = pem(renewed.key.get());
    files.cert = pem(renewed.cert.get());
    write_generation(dir_.path(), "v3", files, false);
    r = pki::check_candidate(dir_.path(), "v3", kServerMtls);
    EXPECT_TRUE(r.generation) << dump(r);

    EXPECT_FALSE(pki::check_candidate(dir_.path(), "../v3", kServerMtls).generation);

    // Serveur sans mTLS : la nouvelle identité doit se rattacher aux racines courantes.
    r = pki::check_candidate(dir_.path(), "v2", kServer);
    EXPECT_FALSE(r.generation);
    EXPECT_TRUE(has(r.errors, "v2", "ne se rattache à aucune racine")) << dump(r);
}

TEST_F(PkiTest, ActivateReplacesCurrentPointer) {
    write_generation(dir_.path(), "v1", server_files(*h_));
    write_generation(dir_.path(), "v2", server_files(*h_), false);
    pki::activate(dir_.path(), "v2");
    const auto r = pki::load_current_generation(dir_.path(), kServer);
    ASSERT_TRUE(r.generation) << dump(r);
    EXPECT_EQ(r.generation->name, "v2");
    EXPECT_FALSE(std::filesystem::exists(dir_.path() / "current.tmp"));
    EXPECT_THROW(pki::activate(dir_.path(), "a/b"), std::filesystem::filesystem_error);
}
