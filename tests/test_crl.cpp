// Revocation by CRL (SPEC §7.7): <pki_root>/crl.pem, applied at the handshake
// and on the fly to open channels.

#include "tlsrelay/pki/revocation.hpp"

#include "support/net_helpers.hpp"
#include "support/test_pki.hpp"

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fstream>

using namespace testnet;
using namespace testpki;

namespace {

constexpr const char* kClientSubject = "CN=client.test,O=tlsrelay-test";

// CRL of ca listing the revoked certificates; next_offset: next update, in seconds.
std::string make_crl(const Issued& ca, const std::vector<const X509*>& revoked, long next_offset = 7 * 24 * 3600,
                     const EVP_PKEY* signer = nullptr) {
    X509_CRL* crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca.cert.get()));
    ASN1_TIME* last = X509_gmtime_adj(nullptr, -3600);
    ASN1_TIME* next = X509_gmtime_adj(nullptr, next_offset);
    X509_CRL_set1_lastUpdate(crl, last);
    X509_CRL_set1_nextUpdate(crl, next);
    for (const X509* cert : revoked) {
        X509_REVOKED* r = X509_REVOKED_new();
        X509_REVOKED_set_serialNumber(r, const_cast<ASN1_INTEGER*>(X509_get0_serialNumber(cert)));
        X509_REVOKED_set_revocationDate(r, last);
        X509_CRL_add0_revoked(crl, r);
    }
    X509_CRL_sort(crl);
    X509_CRL_sign(crl, const_cast<EVP_PKEY*>(signer ? signer : ca.key.get()), EVP_sha256());
    ASN1_TIME_free(last);
    ASN1_TIME_free(next);
    tlsrelay::tls::BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509_CRL(bio.get(), crl);
    X509_CRL_free(crl);
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

class CrlTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create()); }
    static void TearDownTestSuite() { delete h_; }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*h_));
        write_generation(client_pki(), "v1", client_files(*h_));
        std::ofstream(whitelist(), std::ios::binary) << "peers:\n  - name: host\n    ip: 127.0.0.1\n    ports: [mtls]\n"
                                                     << "    subject: \"" << kClientSubject << "\"\n";
    }

    std::filesystem::path server_pki() const { return dir_ / "server"; }
    std::filesystem::path client_pki() const { return dir_ / "client"; }
    std::filesystem::path whitelist() const { return dir_ / "whitelist.yaml"; }

    // Write then rename: the service never reads a half-written file.
    static void write_crl(const std::filesystem::path& pki_root, const std::string& content) {
        const auto tmp = pki_root / "crl.tmp";
        std::ofstream(tmp, std::ios::binary) << content;
        std::filesystem::rename(tmp, pki_root / "crl.pem");
    }

    Config server_config(std::uint16_t destination_port, RevokeMode revoke = RevokeMode::immediate) {
        Config c;
        c.mode = Mode::server;
        c.ports[PortKind::mtls].listen = Endpoint{"127.0.0.1", 0};
        c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
        c.destination->dial_timeout = 1s;
        c.credentials = Credentials{server_pki().string()};
        c.whitelist = WhitelistRef{whitelist().string(), revoke};
        c.limits.shutdown_timeout = 1s;
        c.limits.handshake_timeout = 2s;
        return c;
    }

    Config client_config(std::uint16_t server_port) {
        Config c;
        c.mode = Mode::client;
        c.ports[PortKind::mtls] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", server_port}, "relay.test"};
        c.credentials = Credentials{client_pki().string()};
        c.limits.shutdown_timeout = 1s;
        c.limits.handshake_timeout = 2s;
        return c;
    }

    static relay::ServiceOptions fast_reload() {
        relay::ServiceOptions o{false, 2};
        o.watch_interval = 50ms;
        return o;
    }

    static Hierarchy* h_;
    TempDir dir_;
};
Hierarchy* CrlTest::h_ = nullptr;

bool works(TestClient& app, const std::string& data) {
    app.write(data);
    return app.read_exactly(data.size(), 3s) == data;
}

}  // namespace

TEST_F(CrlTest, ServerRefusesRevokedClientCertificate) {
    write_crl(server_pki(), make_crl(h_->clients_ca, {h_->client.cert.get()}));
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    EXPECT_TRUE(app.wait_closed(5s));
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() >= 1; }));
    EXPECT_EQ(echo.accepted(), 0);
    EXPECT_NE(server.service().status_text().find("CRL: 1 certificate(s) revoked"), std::string::npos)
        << server.service().status_text();
}

TEST_F(CrlTest, ClientRefusesRevokedServerCertificate) {
    write_crl(client_pki(), make_crl(h_->servers_ca, {h_->server.cert.get()}));
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    EXPECT_TRUE(app.wait_closed(5s));
    EXPECT_TRUE(eventually([&] { return client.stats().tls_handshake_failures.load() >= 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(CrlTest, CrlOfOtherCertificatesChangesNothing) {
    auto other = make_certificate({.common_name = "other.test", .usage = Usage::client}, &h_->clients_ca);
    // Shared file: CRL of the Servers CA (not applicable on the server side) and of the Clients CA.
    write_crl(server_pki(), make_crl(h_->servers_ca, {h_->server.cert.get()}) +
                                make_crl(h_->clients_ca, {other.cert.get()}));
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port(PortKind::mtls)));
    TestClient app(client.port(PortKind::mtls));
    EXPECT_TRUE(works(app, "accepted"));
}

TEST_F(CrlTest, PublishedCrlClosesActiveChannelAndRefusesNewOnes) {
    write_crl(server_pki(), make_crl(h_->clients_ca, {}));
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "before"));

    write_crl(server_pki(), make_crl(h_->clients_ca, {h_->client.cert.get()}));
    EXPECT_TRUE(app.wait_closed(5s));
    EXPECT_TRUE(eventually([&] { return server.stats().certificates_revoked.load() == 1; }));
    TestClient again(client.port(PortKind::mtls));
    EXPECT_TRUE(again.wait_closed(5s));
}

TEST_F(CrlTest, NextRenegotiationKeepsActiveChannel) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), RevokeMode::next_renegotiation), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "before"));
    write_crl(server_pki(), make_crl(h_->clients_ca, {h_->client.cert.get()}));
    EXPECT_TRUE(eventually([&] {
        return server.service().status_text().find("CRL: 1 certificate(s)") != std::string::npos;
    }));
    EXPECT_TRUE(works(app, "still open"));
    EXPECT_EQ(server.stats().certificates_revoked.load(), 0u);
}

TEST_F(CrlTest, InvalidCrlIsRefusedAtStartupAndKeptAsIsOnReload) {
    // Signed by a key other than the Clients CA's.
    const auto forged = make_crl(h_->clients_ca, {}, 7 * 24 * 3600, h_->servers_ca.key.get());
    write_crl(server_pki(), forged);
    try {
        relay::Service service(without_default_admin(server_config(9)));
        FAIL() << "the service should have refused to start";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("invalid signature"), std::string::npos) << e.what();
    }

    write_crl(server_pki(), make_crl(h_->clients_ca, {}));
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));
    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "before"));

    write_crl(server_pki(), "not a CRL\n");
    EXPECT_TRUE(eventually([&] { return server.stats().crl_reload_failures.load() == 1; }));
    EXPECT_TRUE(works(app, "still open"));
    TestClient other(client.port(PortKind::mtls));
    EXPECT_TRUE(works(other, "new connection accepted"));
}

TEST_F(CrlTest, ExpiredCrlIsStillAppliedWithWarning) {
    const auto pem = make_crl(h_->clients_ca, {h_->client.cert.get()}, -60);
    write_crl(server_pki(), pem);
    tlsrelay::pki::Requirements req{tlsrelay::pki::Role::server, true, true};
    const auto gen = tlsrelay::pki::load_current_generation(server_pki(), req);
    ASSERT_TRUE(gen.generation);
    const auto result = tlsrelay::pki::load_revocations(server_pki() / "crl.pem", *gen.generation);
    ASSERT_TRUE(result.list);
    EXPECT_TRUE(result.list->is_revoked(h_->client.cert.get()));
    EXPECT_FALSE(result.list->is_revoked(h_->server.cert.get()));
    ASSERT_EQ(result.warnings.size(), 1u);
    EXPECT_NE(result.warnings[0].message.find("stale"), std::string::npos);

    // No CRL for the expected CA: warning, no revocation.
    write_crl(server_pki(), make_crl(h_->servers_ca, {h_->client.cert.get()}));
    const auto none = tlsrelay::pki::load_revocations(server_pki() / "crl.pem", *gen.generation);
    ASSERT_TRUE(none.list);
    EXPECT_FALSE(none.list->is_revoked(h_->client.cert.get()));
    ASSERT_FALSE(none.warnings.empty());
    EXPECT_NE(none.warnings.back().message.find("no CRL for CA"), std::string::npos);
}

TEST_F(CrlTest, RevokedInstanceCertificateIsReported) {
    // Server side: the Servers CA's CRL reports that its own certificate is revoked.
    write_crl(server_pki(), make_crl(h_->servers_ca, {h_->server.cert.get()}) + make_crl(h_->clients_ca, {}));
    tlsrelay::pki::Requirements req{tlsrelay::pki::Role::server, true, true};
    const auto gen = tlsrelay::pki::load_current_generation(server_pki(), req);
    ASSERT_TRUE(gen.generation);
    const auto result = tlsrelay::pki::load_revocations(server_pki() / "crl.pem", *gen.generation);
    ASSERT_TRUE(result.list);
    bool reported = false;
    for (const auto& w : result.warnings) reported |= w.message.find("this instance") != std::string::npos;
    EXPECT_TRUE(reported);
}
