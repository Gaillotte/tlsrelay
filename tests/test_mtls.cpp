// Tests d'intégration mTLS et liste blanche (phase 3, SPEC §3 et §6).

#include "support/net_helpers.hpp"
#include "support/raw_tls_client.hpp"
#include "support/test_pki.hpp"

#include <gtest/gtest.h>

#include <fstream>

using namespace testnet;
using namespace testpki;

namespace {

constexpr const char* kClientSubject = "CN=client.test,O=tlsrelay-test";

class MtlsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create()); }
    static void TearDownTestSuite() { delete h_; }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*h_));
        write_generation(client_pki(), "v1", client_files(*h_));
        allow(std::string("    subject: \"") + kClientSubject + "\"\n");
    }

    std::filesystem::path server_pki() const { return dir_ / "serveur"; }
    std::filesystem::path client_pki() const { return dir_ / "client"; }
    std::filesystem::path whitelist() const { return dir_ / "whitelist.yaml"; }

    // Liste blanche d'une seule entrée (127.0.0.1, port mtls) complétée par extra.
    void allow(const std::string& extra, const std::string& ip = "127.0.0.1", const std::string& ports = "[mtls]") {
        write_whitelist("peers:\n  - name: poste\n    ip: " + ip + "\n    ports: " + ports + "\n" + extra);
    }

    void write_whitelist(const std::string& content) {
        // Écriture dans un fichier temporaire puis renommage : le service ne lit jamais un fichier à moitié écrit.
        const auto tmp = dir_ / "whitelist.tmp";
        std::ofstream(tmp, std::ios::binary) << content;
        std::filesystem::rename(tmp, whitelist());
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

    Config client_config(std::uint16_t server_port, std::optional<std::string> source = std::nullopt) {
        Config c;
        c.mode = Mode::client;
        c.ports[PortKind::mtls] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", server_port}, "relay.test"};
        c.credentials = Credentials{client_pki().string()};
        c.source_address = source;
        c.limits.shutdown_timeout = 1s;
        c.limits.handshake_timeout = 2s;
        return c;
    }

    static relay::ServiceOptions fast_reload() {
        relay::ServiceOptions o{false, 2};
        o.whitelist_poll = 50ms;
        return o;
    }

    static Hierarchy* h_;
    TempDir dir_;
};
Hierarchy* MtlsTest::h_ = nullptr;

bool works(TestClient& app, const std::string& data) {
    app.write(data);
    return app.read_exactly(data.size(), 3s) == data;
}

}  // namespace

TEST_F(MtlsTest, ChainPreservesDataIntegrity) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    std::string sent;
    const auto received = exchange(app, 512 * 1024, 21, &sent);
    EXPECT_EQ(sha256(received), sha256(sent));
    EXPECT_EQ(server.stats().tls_handshake_failures.load(), 0u);
    EXPECT_EQ(server.stats().peers_rejected.load(), 0u);
}

TEST_F(MtlsTest, ServerRejectsClientWithoutCertificate) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));

    RawTlsClient raw(server.port(PortKind::mtls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    raw.handshake();  // en TLS 1.3, le refus du serveur arrive après le handshake côté client
    EXPECT_EQ(raw.read(1), "");
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(MtlsTest, ServerRejectsClientCertificateFromUnexpectedCa) {
    // Même racine, AC intermédiaire différente de l'AC Clients attendue.
    auto other_ca = make_certificate({.common_name = "Test AC Clients bis", .ca = true, .usage = Usage::client,
                                      .curve = "P-384"}, &h_->root);
    auto cert = make_certificate({.common_name = "client.test", .usage = Usage::client}, &other_ca);
    EchoServer echo;
    RunningService server(server_config(echo.port()));

    RawTlsClient raw(server.port(PortKind::mtls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get(), &cert,
                     other_ca.cert.get());
    raw.handshake();
    EXPECT_EQ(raw.read(1), "");
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(MtlsTest, ServerRejectsServerCertificateUsedAsClientCertificate) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));

    RawTlsClient raw(server.port(PortKind::mtls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get(), &h_->server,
                     h_->servers_ca.cert.get());
    raw.handshake();
    EXPECT_EQ(raw.read(1), "");
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(MtlsTest, WhitelistRejectsUnknownSubjectBeforeContactingDestination) {
    allow("    subject: \"CN=autre.test,O=tlsrelay-test\"\n");
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return server.stats().peers_rejected.load() == 1; }));
    EXPECT_EQ(server.stats().tls_handshake_failures.load(), 0u);  // le handshake était valide
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(MtlsTest, WhitelistRequiresIpAndSubjectInTheSameEntry) {
    // Le sujet du client est autorisé depuis 127.0.0.2 seulement ; 127.0.0.1 a une autre entrée.
    write_whitelist(std::string("peers:\n") +
                    "  - { name: client-2, ip: 127.0.0.2, ports: [mtls], subject: \"" + kClientSubject + "\" }\n" +
                    "  - { name: autre-1, ip: 127.0.0.1, ports: [mtls], subject: \"CN=autre.test,O=tlsrelay-test\" }\n");
    EchoServer echo;
    RunningService server(server_config(echo.port()));

    {
        RunningService client(client_config(server.port(PortKind::mtls)));  // source 127.0.0.1
        TestClient app(client.port(PortKind::mtls));
        EXPECT_TRUE(app.wait_closed(3s));
        EXPECT_TRUE(eventually([&] { return server.stats().peers_rejected.load() == 1; }));
    }
    {
        RunningService client(client_config(server.port(PortKind::mtls), "127.0.0.2"));
        TestClient app(client.port(PortKind::mtls));
        EXPECT_TRUE(works(app, "depuis 127.0.0.2"));
    }
    EXPECT_EQ(server.stats().peers_rejected.load(), 1u);
}

TEST_F(MtlsTest, UnknownAddressIsRejectedBeforeHandshake) {
    allow(std::string("    subject: \"") + kClientSubject + "\"\n", "127.0.0.2");
    EchoServer echo;
    RunningService server(server_config(echo.port()));

    TestClient raw(server.port(PortKind::mtls));  // depuis 127.0.0.1
    EXPECT_TRUE(raw.wait_closed(2s));
    EXPECT_TRUE(eventually([&] { return server.stats().peers_rejected.load() == 1; }));
    EXPECT_EQ(server.stats().tls_handshake_failures.load(), 0u);  // aucun handshake tenté
    EXPECT_EQ(server.stats().channels_opened.load(), 0u);
}

TEST_F(MtlsTest, PeerIsLimitedToItsPorts) {
    // Entrée autorisée sur tls seulement : le port plain la refuse.
    write_whitelist("peers:\n  - { name: poste, ip: 127.0.0.1, ports: [tls] }\n");
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.ports.clear();
    cfg.ports[PortKind::plain].listen = Endpoint{"127.0.0.1", 0};
    cfg.ports[PortKind::tls].listen = Endpoint{"127.0.0.1", 0};
    RunningService server(std::move(cfg));

    TestClient plain(server.port(PortKind::plain));
    EXPECT_TRUE(plain.wait_closed(2s));
    EXPECT_EQ(server.stats().peers_rejected.load(), 1u);

    RawTlsClient tls(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(tls.handshake());
    ASSERT_TRUE(tls.write("ok"));
    EXPECT_EQ(tls.read(2), "ok");
}

TEST_F(MtlsTest, ReloadRevokesActiveChannelOfRemovedPeer) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "avant"));

    write_whitelist("peers: []\n");  // pair retiré
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return server.stats().peers_revoked.load() == 1; }));

    TestClient again(client.port(PortKind::mtls));  // les nouvelles connexions sont refusées
    EXPECT_TRUE(again.wait_closed(3s));
}

TEST_F(MtlsTest, ReloadWithNextRenegotiationKeepsActiveChannel) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), RevokeMode::next_renegotiation), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "avant"));

    write_whitelist("peers: []\n");
    // Attend que la nouvelle liste soit en vigueur : une nouvelle connexion est refusée.
    EXPECT_TRUE(eventually([&] {
        TestClient probe(client.port(PortKind::mtls));
        return probe.wait_closed(500ms);
    }));
    EXPECT_TRUE(works(app, "toujours ouvert"));
    EXPECT_EQ(server.stats().peers_revoked.load(), 0u);
}

TEST_F(MtlsTest, InvalidReloadKeepsCurrentList) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));

    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "avant"));

    write_whitelist("peers:\n  - name: incomplet\n");  // ip manquante : fichier refusé
    std::this_thread::sleep_for(300ms);
    EXPECT_TRUE(works(app, "toujours ouvert"));
    TestClient other(client.port(PortKind::mtls));
    EXPECT_TRUE(works(other, "nouvelle connexion acceptée"));
    EXPECT_EQ(server.stats().peers_revoked.load(), 0u);
}

TEST_F(MtlsTest, ReloadAddsPeer) {
    write_whitelist("peers: []\n");
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_reload());
    RunningService client(client_config(server.port(PortKind::mtls)));

    {
        TestClient refused(client.port(PortKind::mtls));
        EXPECT_TRUE(refused.wait_closed(3s));
    }
    allow(std::string("    subject: \"") + kClientSubject + "\"\n");
    EXPECT_TRUE(eventually([&] {
        TestClient app(client.port(PortKind::mtls));
        return works(app, "ajouté");
    }));
}

TEST_F(MtlsTest, ServiceRefusesInvalidWhitelistAtStartup) {
    write_whitelist("peers:\n  - { name: a, ip: 999.0.0.1 }\n");
    try {
        relay::Service service(server_config(9));
        FAIL() << "le service aurait dû refuser de démarrer";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("adresse IP invalide"), std::string::npos) << e.what();
    }
}
