// Security campaign (phase 10, PLAN §5.4): automated attack cases that
// complement those of the previous phases (TLS 1.2, ALPN, other PKI, wrong
// usage, replayed or forged token, unknown frame: test_tls, test_mtls,
// test_tunnel). Each test checks the refusal and the absence of effect: nothing
// reaches the destination or the fake server.

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
        std::ofstream(whitelist()) << "peers:\n  - { name: workstation, ip: 127.0.0.1, ports: [tls, mtls], subject: \""
                                   << kClientSubject << "\" }\n";
    }

    std::filesystem::path server_pki() const { return dir_ / "server"; }
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

    // Client certificate issued by the Clients CA, valid between not_before and not_after (seconds from now).
    static Issued client_cert(long not_before, long not_after) {
        return make_certificate({.common_name = "client.test",
                                 .usage = Usage::client,
                                 .not_before_offset = not_before,
                                 .not_after_offset = not_after},
                                &h_->clients_ca);
    }

    // Server certificate (relay.test, 127.0.0.1) issued by the Servers CA.
    static Issued server_cert(Usage usage, long not_before, long not_after) {
        return make_certificate({.common_name = "relay.test",
                                 .usage = usage,
                                 .dns = {"relay.test"},
                                 .ips = {"127.0.0.1"},
                                 .not_before_offset = not_before,
                                 .not_after_offset = not_after},
                                &h_->servers_ca);
    }

    // The server refuses the presented client certificate: the connection is closed,
    // the destination is never contacted.
    void expect_client_certificate_refused(const Issued& cert) {
        EchoServer echo;
        RunningService server(server_config(echo.port()));
        RawTlsClient raw(server.port(PortKind::mtls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get(), &cert,
                         h_->clients_ca.cert.get());
        raw.handshake();  // with TLS 1.3, the server's refusal arrives after the handshake on the client side
        EXPECT_EQ(raw.read(1), "");
        EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
        EXPECT_EQ(echo.accepted(), 0);
    }

    // The tlsrelay client refuses the fake server: no application data
    // reaches it and the application sees its connection closed.
    void expect_server_certificate_refused(const Issued& cert) {
        RawTlsServer fake(cert, h_->servers_ca.cert.get());
        RunningService client(client_config(fake.port()));
        TestClient app(client.port(PortKind::mtls));
        app.write("application secret");
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

// --- Certificates outside their validity period ------------------------------

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
    // Certificate from the Servers CA, but for client use (extendedKeyUsage clientAuth).
    expect_server_certificate_refused(server_cert(Usage::client, -3600, 3600));
}

TEST_F(AttackTest, ClientSendsNothingToValidFakeServerWithoutTunnelProtocol) {
    // With a valid certificate, the fake server gets the handshake and the OPEN
    // frame, never the application data: it waits for OPEN_OK.
    const auto cert = server_cert(Usage::server, -3600, 3600);
    RawTlsServer fake(cert, h_->servers_ca.cert.get());
    {
        RunningService client(client_config(fake.port()));
        TestClient app(client.port(PortKind::mtls));
        app.write("application secret");
        EXPECT_TRUE(eventually([&] { return fake.handshakes() >= 1; }));
        EXPECT_TRUE(eventually([&] { return fake.received() > 0; }));
        std::this_thread::sleep_for(200ms);
    }
    const auto data = fake.data();
    ASSERT_GE(data.size(), tlsrelay::tunnel::kHeaderSize);
    EXPECT_EQ(static_cast<FrameType>(data[0]), FrameType::open);
    EXPECT_EQ(data.find("application secret"), std::string::npos);
}

// --- Tunnel frames -----------------------------------------------------------

TEST_F(AttackTest, DataWithUnexpectedSequenceClosesChannel) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls));
    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    ASSERT_TRUE(probe.open(PortKind::tls));
    ASSERT_TRUE(raw.write(tlsrelay::tunnel::encode_data(5, "abc", 3)));  // expected seq: 1
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
    // DATA header announcing 1 GiB: refused from the header alone, without waiting for or allocating the payload.
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
    ASSERT_TRUE(raw.write(tlsrelay::tunnel::encode_data(1, "abc", 3)));  // no OPEN
    TunnelProbe probe(raw);
    const auto frame = probe.next();
    ASSERT_TRUE(frame);
    EXPECT_EQ(frame->type, FrameType::close);
    EXPECT_EQ(tlsrelay::tunnel::read_status(*frame).code, static_cast<std::uint16_t>(CloseCode::protocol_error));
    EXPECT_EQ(echo.accepted(), 0);
}

// --- Connection flood without handshake --------------------------------------

TEST_F(AttackTest, ConnectionFloodWithoutHandshakeIsBoundedAndRecovers) {
    EchoServer echo;
    auto cfg = server_config(echo.port(), PortKind::tls);
    cfg.limits.max_channels = 10;
    cfg.limits.handshake_timeout = 1s;
    RunningService server(std::move(cfg));
    const auto port = server.port(PortKind::tls);

    // 30 silent connections: 10 take the handshake slots, the others are refused at once.
    asio::io_context io;
    std::vector<tcp::socket> flood;
    for (int i = 0; i < 30; ++i) {
        flood.emplace_back(io);
        flood.back().connect(tcp::endpoint(loopback(), port));
    }
    EXPECT_TRUE(eventually([&] { return server.stats().channels_rejected.load() == 20; }));

    // All are closed by the server: immediate refusal or handshake timeout.
    for (auto& s : flood) {
        s.non_blocking(false);
        std::array<char, 16> buffer{};
        std::error_code ec;
        s.read_some(asio::buffer(buffer), ec);
        EXPECT_TRUE(ec) << "silent connection left open";
    }
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 10; }));

    // The service remains available for a legitimate peer.
    RawTlsClient raw(port, TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    EXPECT_TRUE(probe.open(PortKind::tls));
}

// --- Logs: neither secrets nor relayed data -----------------------------------

TEST_F(AttackTest, TraceLogsContainNoSecretsNorRelayedData) {
    const auto log_path = dir_ / "trace.log";
    tlsrelay::LogConfig log;
    log.level = tlsrelay::LogLevel::trace;
    log.output = log_path.string();
    tlsrelay::logging::init(log);

    const std::string marker = "RELAYED-DATA-7f3a9c";
    {
        EchoServer echo;
        RunningService server(server_config(echo.port()));
        RunningService client(client_config(server.port(PortKind::mtls)));
        TestClient app(client.port(PortKind::mtls));
        app.write(marker);
        EXPECT_EQ(app.read_exactly(marker.size(), 3s), marker);
    }
    tlsrelay::logging::init_default();  // releases the file

    const auto logs = read_file(log_path);
    ASSERT_NE(logs.find("TLS established"), std::string::npos) << "trace level log expected";
    EXPECT_EQ(logs.find(marker), std::string::npos) << "relayed data in the logs";
    EXPECT_EQ(logs.find(to_hex(marker)), std::string::npos) << "relayed data (hexadecimal) in the logs";
    EXPECT_EQ(logs.find("PRIVATE KEY"), std::string::npos);
    // No line of the private keys (PEM) of the two relays.
    for (const auto* key : {h_->server.key.get(), h_->client.key.get()}) {
        std::istringstream lines(pem(key));
        std::string line;
        while (std::getline(lines, line)) {
            if (line.size() < 32 || line.starts_with("-----")) continue;
            EXPECT_EQ(logs.find(line), std::string::npos) << "private key in the logs";
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
        // CLOSE with a code other than NORMAL: the server logs the peer's message.
        ASSERT_TRUE(raw.write(tlsrelay::tunnel::encode_close(
            static_cast<std::uint16_t>(CloseCode::internal_error), "end\nINJECTED [config] fake\r\x1b[2J")));
        EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    }
    tlsrelay::logging::init_default();

    const auto logs = read_file(log_path);
    ASSERT_NE(logs.find("closed by the other tlsrelay"), std::string::npos) << logs;
    std::istringstream lines(logs);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();  // CRLF line ending on Windows
        EXPECT_FALSE(line.starts_with("INJECTED")) << "injected line: " << line;
        EXPECT_EQ(line.find('\x1b'), std::string::npos) << "escape sequence in the logs";
        EXPECT_EQ(line.find('\r'), std::string::npos);
    }
}
