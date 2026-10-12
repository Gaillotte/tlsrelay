// Campagne de sécurité (phase 10, PLAN §5.4) : cas d'attaque automatisés qui
// complètent ceux des phases précédentes (TLS 1.2, ALPN, autre PKI, mauvais
// usage, jeton rejoué ou falsifié, trame inconnue : test_tls, test_mtls,
// test_tunnel). Chaque test vérifie le refus et l'absence d'effet : rien
// n'atteint la destination ni le faux serveur.

#include "support/net_helpers.hpp"
#include "support/raw_tls_client.hpp"
#include "support/raw_tls_server.hpp"
#include "support/test_pki.hpp"

#include "tlsrelay/logging.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

using namespace testnet;
using namespace testpki;
using tlsrelay::tunnel::CloseCode;
using tlsrelay::tunnel::FrameType;

namespace {

constexpr const char* kClientSubject = "CN=client.test,O=tlsrelay-test";

class AttackTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create("A")); }
    static void TearDownTestSuite() { delete h_; }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*h_));
        write_generation(client_pki(), "v1", client_files(*h_));
        std::ofstream(whitelist()) << "peers:\n  - { name: poste, ip: 127.0.0.1, ports: [tls, mtls], subject: \""
                                   << kClientSubject << "\" }\n";
    }

    std::filesystem::path server_pki() const { return dir_ / "serveur"; }
    std::filesystem::path client_pki() const { return dir_ / "client"; }
    std::filesystem::path whitelist() const { return dir_ / "whitelist.yaml"; }

    Config server_config(std::uint16_t destination_port, PortKind kind = PortKind::mtls) {
        Config c;
        c.mode = Mode::server;
        c.ports[kind].listen = Endpoint{"127.0.0.1", 0};
        c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
        c.destination->dial_timeout = 1s;
        c.credentials = Credentials{server_pki().string()};
        c.whitelist = WhitelistRef{whitelist().string()};
        c.limits.handshake_timeout = 2s;
        c.limits.shutdown_timeout = 1s;
        return c;
    }

    Config client_config(std::uint16_t upstream_port, PortKind kind = PortKind::mtls) {
        Config c;
        c.mode = Mode::client;
        c.ports[kind] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", upstream_port}, "relay.test"};
        c.credentials = Credentials{client_pki().string()};
        c.limits.handshake_timeout = 2s;
        c.limits.shutdown_timeout = 1s;
        return c;
    }

    // Certificat client émis par l'AC Clients, valable entre not_before et not_after (secondes depuis maintenant).
    static Issued client_cert(long not_before, long not_after) {
        return make_certificate({.common_name = "client.test",
                                 .usage = Usage::client,
                                 .not_before_offset = not_before,
                                 .not_after_offset = not_after},
                                &h_->clients_ca);
    }

    // Certificat serveur (relay.test, 127.0.0.1) émis par l'AC Serveurs.
    static Issued server_cert(Usage usage, long not_before, long not_after) {
        return make_certificate({.common_name = "relay.test",
                                 .usage = usage,
                                 .dns = {"relay.test"},
                                 .ips = {"127.0.0.1"},
                                 .not_before_offset = not_before,
                                 .not_after_offset = not_after},
                                &h_->servers_ca);
    }

    // Le serveur refuse le certificat client présenté : la connexion est fermée,
    // la destination n'est jamais contactée.
    void expect_client_certificate_refused(const Issued& cert) {
        EchoServer echo;
        RunningService server(server_config(echo.port()));
        RawTlsClient raw(server.port(PortKind::mtls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get(), &cert,
                         h_->clients_ca.cert.get());
        raw.handshake();  // en TLS 1.3, le refus du serveur arrive après le handshake côté client
        EXPECT_EQ(raw.read(1), "");
        EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
        EXPECT_EQ(echo.accepted(), 0);
    }

    // Le client tlsrelay refuse le faux serveur : aucune donnée de l'application
    // ne lui parvient et l'application voit sa connexion fermée.
    void expect_server_certificate_refused(const Issued& cert) {
        RawTlsServer fake(cert, h_->servers_ca.cert.get());
        RunningService client(client_config(fake.port()));
        TestClient app(client.port(PortKind::mtls));
        app.write("secret de l'application");
        EXPECT_TRUE(app.wait_closed(5s));
        EXPECT_GE(client.stats().tls_handshake_failures.load(), 1u);
        EXPECT_EQ(fake.handshakes(), 0);
        EXPECT_EQ(fake.received(), 0u);
    }

    static Hierarchy* h_;
    TempDir dir_;
};
Hierarchy* AttackTest::h_ = nullptr;

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream content;
    content << in.rdbuf();
    return content.str();
}

std::string to_hex(const std::string& data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (const unsigned char c : data) {
        out += digits[c >> 4];
        out += digits[c & 0xf];
    }
    return out;
}

}  // namespace

// --- Certificats hors de leur période de validité ----------------------------

TEST_F(AttackTest, ServerRejectsExpiredClientCertificate) {
    expect_client_certificate_refused(client_cert(-7200, -3600));
}

TEST_F(AttackTest, ServerRejectsNotYetValidClientCertificate) {
    expect_client_certificate_refused(client_cert(3600, 7200));
}

TEST_F(AttackTest, ClientRejectsExpiredServerCertificate) {
    expect_server_certificate_refused(server_cert(Usage::server, -7200, -3600));
}

TEST_F(AttackTest, ClientRejectsNotYetValidServerCertificate) {
    expect_server_certificate_refused(server_cert(Usage::server, 3600, 7200));
}

TEST_F(AttackTest, ClientRejectsServerPresentingClientCertificate) {
    // Certificat de l'AC Serveurs, mais à usage client (extendedKeyUsage clientAuth).
    expect_server_certificate_refused(server_cert(Usage::client, -3600, 3600));
}

TEST_F(AttackTest, ClientSendsNothingToValidFakeServerWithoutTunnelProtocol) {
    // Avec un certificat valide, le faux serveur obtient le handshake et la trame
    // OPEN, jamais les données de l'application : elles attendent OPEN_OK.
    const auto cert = server_cert(Usage::server, -3600, 3600);
    RawTlsServer fake(cert, h_->servers_ca.cert.get());
    {
        RunningService client(client_config(fake.port()));
        TestClient app(client.port(PortKind::mtls));
        app.write("secret de l'application");
        EXPECT_TRUE(eventually([&] { return fake.handshakes() >= 1; }));
        EXPECT_TRUE(eventually([&] { return fake.received() > 0; }));
        std::this_thread::sleep_for(200ms);
    }
    const auto data = fake.data();
    ASSERT_GE(data.size(), tlsrelay::tunnel::kHeaderSize);
    EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::open);
    EXPECT_EQ(data.find("secret de l'application"), std::string::npos);
}

// --- Trames du tunnel --------------------------------------------------------

TEST_F(AttackTest, DataWithUnexpectedSequenceClosesChannel) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls));
    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    ASSERT_TRUE(probe.open(PortKind::tls));
    ASSERT_TRUE(raw.write(tlsrelay::tunnel::encode_data(5, "abc", 3)));  // seq attendu : 1
    std::optional<tlsrelay::tunnel::Frame> frame;
    do {
        frame = probe.next();
    } while (frame && frame->type != FrameType::close);
    ASSERT_TRUE(frame);
    EXPECT_EQ(tlsrelay::tunnel::read_status(*frame).code, static_cast<std::uint16_t>(CloseCode::protocol_error));
    EXPECT_EQ(server.stats().protocol_errors.load(), 1u);
}

TEST_F(AttackTest, OversizedFrameHeaderClosesChannelBeforePayload) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls));
    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    ASSERT_TRUE(probe.open(PortKind::tls));
    // En-tête DATA annonçant 1 Gio : refusé dès l'en-tête, sans attendre ni allouer la charge utile.
    ASSERT_TRUE(raw.write(std::string("\x10\0\0\0\x40\0\0\0", 8)));
    std::optional<tlsrelay::tunnel::Frame> frame;
    do {
        frame = probe.next();
    } while (frame && frame->type != FrameType::close);
    ASSERT_TRUE(frame);
    EXPECT_EQ(tlsrelay::tunnel::read_status(*frame).code, static_cast<std::uint16_t>(CloseCode::frame_too_large));
    EXPECT_EQ(server.stats().protocol_errors.load(), 1u);
}

TEST_F(AttackTest, DataBeforeOpenIsRefused) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls));
    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    ASSERT_TRUE(raw.write(tlsrelay::tunnel::encode_data(1, "abc", 3)));  // pas d'OPEN
    TunnelProbe probe(raw);
    const auto frame = probe.next();
    ASSERT_TRUE(frame);
    EXPECT_EQ(frame->type, FrameType::close);
    EXPECT_EQ(tlsrelay::tunnel::read_status(*frame).code, static_cast<std::uint16_t>(CloseCode::protocol_error));
    EXPECT_EQ(echo.accepted(), 0);
}

// --- Inondation de connexions sans handshake ---------------------------------

TEST_F(AttackTest, ConnectionFloodWithoutHandshakeIsBoundedAndRecovers) {
    EchoServer echo;
    auto cfg = server_config(echo.port(), PortKind::tls);
    cfg.limits.max_channels = 10;
    cfg.limits.handshake_timeout = 1s;
    RunningService server(std::move(cfg));
    const auto port = server.port(PortKind::tls);

    // 30 connexions muettes : 10 occupent les places de handshake, les autres sont refusées aussitôt.
    asio::io_context io;
    std::vector<tcp::socket> flood;
    for (int i = 0; i < 30; ++i) {
        flood.emplace_back(io);
        flood.back().connect(tcp::endpoint(loopback(), port));
    }
    EXPECT_TRUE(eventually([&] { return server.stats().channels_rejected.load() == 20; }));

    // Toutes sont fermées par le serveur : refus immédiat ou délai de handshake dépassé.
    for (auto& s : flood) {
        s.non_blocking(false);
        std::array<char, 16> buffer{};
        std::error_code ec;
        s.read_some(asio::buffer(buffer), ec);
        EXPECT_TRUE(ec) << "connexion muette restée ouverte";
    }
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 10; }));

    // Le service reste disponible pour un pair légitime.
    RawTlsClient raw(port, TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    EXPECT_TRUE(probe.open(PortKind::tls));
}

// --- Journaux : ni secrets ni données relayées --------------------------------

TEST_F(AttackTest, TraceLogsContainNoSecretsNorRelayedData) {
    const auto log_path = dir_ / "trace.log";
    tlsrelay::LogConfig log;
    log.level = tlsrelay::LogLevel::trace;
    log.output = log_path.string();
    tlsrelay::logging::init(log);

    const std::string marker = "DONNEE-RELAYEE-7f3a9c";
    {
        EchoServer echo;
        RunningService server(server_config(echo.port()));
        RunningService client(client_config(server.port(PortKind::mtls)));
        TestClient app(client.port(PortKind::mtls));
        app.write(marker);
        EXPECT_EQ(app.read_exactly(marker.size(), 3s), marker);
    }
    tlsrelay::logging::init_default();  // libère le fichier

    const auto logs = read_file(log_path);
    ASSERT_NE(logs.find("TLS établi"), std::string::npos) << "journal de niveau trace attendu";
    EXPECT_EQ(logs.find(marker), std::string::npos) << "données relayées dans les journaux";
    EXPECT_EQ(logs.find(to_hex(marker)), std::string::npos) << "données relayées (hexadécimal) dans les journaux";
    EXPECT_EQ(logs.find("PRIVATE KEY"), std::string::npos);
    // Aucune ligne des clés privées (PEM) des deux relais.
    for (const auto* key : {h_->server.key.get(), h_->client.key.get()}) {
        std::istringstream lines(pem(key));
        std::string line;
        while (std::getline(lines, line)) {
            if (line.size() < 32 || line.starts_with("-----")) continue;
            EXPECT_EQ(logs.find(line), std::string::npos) << "clé privée dans les journaux";
        }
    }
}

TEST_F(AttackTest, PeerMessageCannotInjectLogLines) {
    const auto log_path = dir_ / "injection.log";
    tlsrelay::LogConfig log;
    log.output = log_path.string();
    tlsrelay::logging::init(log);
    {
        EchoServer echo;
        RunningService server(server_config(echo.port(), PortKind::tls));
        RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
        ASSERT_TRUE(raw.handshake());
        TunnelProbe probe(raw);
        ASSERT_TRUE(probe.open(PortKind::tls));
        // CLOSE d'un code autre que NORMAL : le serveur journalise le message du pair.
        ASSERT_TRUE(raw.write(tlsrelay::tunnel::encode_close(
            static_cast<std::uint16_t>(CloseCode::internal_error), "fin\nINJECTE [config] faux\r\x1b[2J")));
        EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    }
    tlsrelay::logging::init_default();

    const auto logs = read_file(log_path);
    ASSERT_NE(logs.find("fermé par l'autre tlsrelay"), std::string::npos) << logs;
    std::istringstream lines(logs);
    std::string line;
    while (std::getline(lines, line)) {
        EXPECT_FALSE(line.starts_with("INJECTE")) << "ligne injectée : " << line;
        EXPECT_EQ(line.find('\x1b'), std::string::npos) << "séquence d'échappement dans les journaux";
        EXPECT_EQ(line.find('\r'), std::string::npos);
    }
}
