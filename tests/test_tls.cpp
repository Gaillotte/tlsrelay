// TLS 1.3 integration tests (phase 2): tls port between a client tlsrelay
// and a server tlsrelay, and refusal cases (SPEC §3, PLAN §5.3 and §5.4).

#include "support/net_helpers.hpp"
#include "support/raw_tls_client.hpp"
#include "support/test_pki.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <gtest/gtest.h>

#include <csignal>
#include <optional>

using namespace testnet;
using namespace testpki;

namespace {

Config tls_server_config(std::uint16_t destination_port, const std::filesystem::path& pki_root) {
    Config c;
    c.mode = Mode::server;
    c.ports[PortKind::tls].listen = Endpoint{"127.0.0.1", 0};
    c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
    c.whitelist = WhitelistRef{permissive_whitelist()};
    c.destination->dial_timeout = 1s;
    c.credentials = Credentials{pki_root.string()};
    c.limits.shutdown_timeout = 1s;
    c.limits.handshake_timeout = 2s;
    return c;
}

Config tls_client_config(std::uint16_t server_port, const std::filesystem::path& pki_root,
                         const std::string& server_name = "relay.test") {
    Config c;
    c.mode = Mode::client;
    c.ports[PortKind::tls] =
        PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", server_port}, server_name};
    c.credentials = Credentials{pki_root.string()};
    c.limits.shutdown_timeout = 1s;
    c.limits.handshake_timeout = 2s;
    return c;
}

class TlsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create()); }
    static void TearDownTestSuite() { delete h_; }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*h_));
        write_generation(client_pki(), "v1", client_files(*h_));
    }

    std::filesystem::path server_pki() const { return dir_ / "server"; }
    std::filesystem::path client_pki() const { return dir_ / "client"; }

    static Hierarchy* h_;
    TempDir dir_;
};
Hierarchy* TlsTest::h_ = nullptr;

}  // namespace

TEST_F(TlsTest, ChainPreservesDataIntegrity) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki()));

    {
        TestClient app(client.port(PortKind::tls));
        std::string sent;
        const auto received = exchange(app, 1 << 20, 3, &sent);
        ASSERT_EQ(received.size(), sent.size());
        EXPECT_EQ(sha256(received), sha256(sent));
    }
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    EXPECT_EQ(client.stats().tls_handshake_failures.load(), 0u);
    EXPECT_EQ(server.stats().tls_handshake_failures.load(), 0u);
}

TEST_F(TlsTest, ManyChannelsInParallel) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki()));

    constexpr int kChannels = 20;
    std::atomic<int> ok{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kChannels; ++i) {
        threads.emplace_back([&, i] {
            try {
                TestClient app(client.port(PortKind::tls));
                std::string sent;
                const auto received = exchange(app, 128 * 1024, static_cast<std::uint64_t>(100 + i), &sent);
                if (sha256(received) == sha256(sent)) ++ok;
            } catch (const std::exception&) {
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(ok.load(), kChannels);
}

TEST_F(TlsTest, HalfClosePropagatesOverTls) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki()));

    TestClient app(client.port(PortKind::tls));
    const auto data = make_random_data(64 * 1024, 11);
    app.write(data);
    app.shutdown_send();  // crosses TLS as close_notify
    const auto received = app.read_until_eof(5s);
    EXPECT_EQ(sha256(received), sha256(data));
}

TEST_F(TlsTest, ClientAcceptsIpAddressAsServerName) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki(), "127.0.0.1"));

    TestClient app(client.port(PortKind::tls));
    app.write("ip");
    EXPECT_EQ(app.read_exactly(2), "ip");
}

TEST_F(TlsTest, ClientRejectsServerFromAnotherPki) {
    const auto other = Hierarchy::create("Other");
    write_generation(server_pki(), "v1", server_files(other));
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki()));

    TestClient app(client.port(PortKind::tls));
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return client.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);  // the destination is never contacted
}

TEST_F(TlsTest, ClientRejectsWrongServerName) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki(), "other.test"));

    TestClient app(client.port(PortKind::tls));
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return client.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, ClientRejectsServerCertificateFromUnexpectedCa) {
    // Same root, but the server certificate is issued by a CA other than the expected Servers CA.
    auto other_ca = make_certificate({.common_name = "Test Servers CA bis", .ca = true, .usage = Usage::server,
                                      .curve = "P-384"}, &h_->root);
    auto server_cert = make_certificate({.common_name = "relay.test", .usage = Usage::server, .dns = {"relay.test"}},
                                        &other_ca);
    auto files = server_files(*h_);
    files.key = pem(server_cert.key.get());
    files.cert = pem(server_cert.cert.get());
    files.chain = pem(other_ca.cert.get());
    write_generation(server_pki(), "v1", files);

    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki()));

    TestClient app(client.port(PortKind::tls));
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return client.stats().tls_handshake_failures.load() == 1; }));
    // Refusal during the handshake: the server receives an alert and does not contact the destination.
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, ServerNegotiatesTls13WithAlpn) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));

    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    ASSERT_TRUE(raw.handshake()) << tlsrelay::tls::take_openssl_errors();
    EXPECT_EQ(SSL_version(raw.ssl()), TLS1_3_VERSION);
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(raw.ssl(), &proto, &len);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(proto), len), "tlsrelay/1");
    EXPECT_STREQ(SSL_CIPHER_get_name(SSL_get_current_cipher(raw.ssl())), "TLS_AES_256_GCM_SHA384");
    TunnelProbe tunnel(raw);
    ASSERT_TRUE(tunnel.open(PortKind::tls));
    ASSERT_TRUE(tunnel.send("hello!!"));
    EXPECT_EQ(tunnel.receive(7), "hello!!");
}

TEST_F(TlsTest, ServerRejectsTls12) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));

    RawTlsClient raw(server.port(PortKind::tls), TLS1_2_VERSION, "tlsrelay/1");
    EXPECT_FALSE(raw.handshake());
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, ServerRejectsWrongAlpn) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));

    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "http/1.1");
    EXPECT_FALSE(raw.handshake());
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, ServerRejectsMissingAlpn) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));

    // Without ALPN, the handshake completes on the client side, but the server
    // closes before contacting the destination.
    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, std::nullopt);
    raw.handshake();
    EXPECT_EQ(raw.read(1), "");
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, ServerRejectsPlaintextOnTlsPort) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));

    TestClient plain(server.port(PortKind::tls));
    plain.write("GET / HTTP/1.0\r\n\r\n");
    EXPECT_TRUE(plain.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, HandshakeTimeoutClosesSilentConnection) {
    EchoServer echo;
    auto cfg = tls_server_config(echo.port(), server_pki());
    cfg.limits.handshake_timeout = 300ms;
    RunningService server(std::move(cfg));

    TestClient silent(server.port(PortKind::tls));
    const auto start = Clock::now();
    EXPECT_TRUE(silent.wait_closed(3s));
    EXPECT_GE(Clock::now() - start, 250ms);
    EXPECT_TRUE(eventually([&] { return server.stats().tls_handshake_failures.load() == 1; }));
}

TEST_F(TlsTest, ServiceRefusesToStartWithInvalidPki) {
    auto expired = make_certificate({.common_name = "relay.test", .usage = Usage::server,
                                     .not_before_offset = -7200, .not_after_offset = -3600}, &h_->servers_ca);
    auto files = server_files(*h_);
    files.key = pem(expired.key.get());
    files.cert = pem(expired.cert.get());
    write_generation(server_pki(), "v1", files);

    try {
        relay::Service service(without_default_admin(tls_server_config(9, server_pki())));
        FAIL() << "the service should have refused to start";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("expired"), std::string::npos) << e.what();
    }
}
