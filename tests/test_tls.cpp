// Tests d'intégration TLS 1.3 (phase 2) : port tls entre un tlsrelay client
// et un tlsrelay serveur, et cas de refus (SPEC §3, PLAN §5.3 et §5.4).

#include "support/net_helpers.hpp"
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

// Client TLS « brut » (OpenSSL bloquant) pour simuler des pairs non conformes.
class RawTlsClient {
public:
    RawTlsClient(std::uint16_t port, int max_version, std::optional<std::string> alpn, const X509* root = nullptr)
        : socket_(io_) {
#ifndef _WIN32
        std::signal(SIGPIPE, SIG_IGN);
#endif
        socket_.connect(tcp::endpoint(loopback(), port));
        ctx_.reset(SSL_CTX_new(TLS_client_method()));
        SSL_CTX_set_max_proto_version(ctx_.get(), max_version);
        if (root) {
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx_.get()), const_cast<X509*>(root));
            SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER, nullptr);
        }
        if (alpn) {
            const std::string wire = std::string(1, static_cast<char>(alpn->size())) + *alpn;
            SSL_CTX_set_alpn_protos(ctx_.get(), reinterpret_cast<const unsigned char*>(wire.data()),
                                    static_cast<unsigned>(wire.size()));
        }
        ssl_.reset(SSL_new(ctx_.get()));
        SSL_set_fd(ssl_.get(), static_cast<int>(socket_.native_handle()));
    }

    bool handshake() {
        ERR_clear_error();
        return SSL_connect(ssl_.get()) == 1;
    }

    // Lecture bloquante : retourne vide si le serveur ferme la connexion.
    std::string read(std::size_t n) {
        std::string out(n, '\0');
        std::size_t got = 0;
        while (got < n) {
            std::size_t r = 0;
            if (SSL_read_ex(ssl_.get(), out.data() + got, n - got, &r) != 1) break;
            got += r;
        }
        out.resize(got);
        return out;
    }

    bool write(const std::string& data) {
        std::size_t w = 0;
        return SSL_write_ex(ssl_.get(), data.data(), data.size(), &w) == 1;
    }

    SSL* ssl() { return ssl_.get(); }

private:
    asio::io_context io_;
    tcp::socket socket_;
    tlsrelay::tls::SslCtxPtr ctx_;
    tlsrelay::tls::SslPtr ssl_;
};

class TlsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create()); }
    static void TearDownTestSuite() { delete h_; }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*h_));
        write_generation(client_pki(), "v1", client_files(*h_));
    }

    std::filesystem::path server_pki() const { return dir_ / "serveur"; }
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
    app.shutdown_send();  // traverse le TLS sous forme de close_notify
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
    const auto other = Hierarchy::create("Autre");
    write_generation(server_pki(), "v1", server_files(other));
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki()));

    TestClient app(client.port(PortKind::tls));
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return client.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);  // la destination n'est jamais contactée
}

TEST_F(TlsTest, ClientRejectsWrongServerName) {
    EchoServer echo;
    RunningService server(tls_server_config(echo.port(), server_pki()));
    RunningService client(tls_client_config(server.port(PortKind::tls), client_pki(), "autre.test"));

    TestClient app(client.port(PortKind::tls));
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return client.stats().tls_handshake_failures.load() == 1; }));
    EXPECT_EQ(echo.accepted(), 0);
}

TEST_F(TlsTest, ClientRejectsServerCertificateFromUnexpectedCa) {
    // Même racine, mais le certificat serveur est émis par une autre AC que l'AC Serveurs attendue.
    auto other_ca = make_certificate({.common_name = "Test AC Serveurs bis", .ca = true, .usage = Usage::server,
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
    // Refus pendant le handshake : le serveur reçoit une alerte et ne contacte pas la destination.
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
    ASSERT_TRUE(raw.write("bonjour"));
    EXPECT_EQ(raw.read(7), "bonjour");
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

    // Sans ALPN, le handshake aboutit côté client, mais le serveur ferme avant
    // de contacter la destination.
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
        relay::Service service(tls_server_config(9, server_pki()));
        FAIL() << "le service aurait dû refuser de démarrer";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("expiré"), std::string::npos) << e.what();
    }
}
