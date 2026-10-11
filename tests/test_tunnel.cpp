// Protocole de tunnel et renégociation transparente (phase 5, SPEC §4) :
// renégociation à l'échéance de session_lifetime sans perte ni duplication,
// reprise après coupure du transport, jeton de reprise à usage unique,
// fermeture par le serveur sans renégociation, erreurs de protocole.

#include "support/cut_proxy.hpp"
#include "support/net_helpers.hpp"
#include "support/raw_tls_client.hpp"
#include "support/test_pki.hpp"

#include <gtest/gtest.h>

#include <fstream>

using namespace testnet;
using namespace testpki;
using tlsrelay::tunnel::CloseCode;
using tlsrelay::tunnel::FrameType;

namespace {

constexpr const char* kClientSubject = "CN=client.test,O=tlsrelay-test";

class TunnelTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { h_ = new Hierarchy(Hierarchy::create("T")); }
    static void TearDownTestSuite() { delete h_; }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*h_));
        write_generation(client_pki(), "v1", client_files(*h_));
        std::ofstream(whitelist()) << "peers:\n  - { name: poste, ip: 127.0.0.1, ports: [plain, tls, mtls], subject: \""
                                   << kClientSubject << "\" }\n";
    }

    std::filesystem::path server_pki() const { return dir_ / "serveur"; }
    std::filesystem::path client_pki() const { return dir_ / "client"; }
    std::filesystem::path whitelist() const { return dir_ / "whitelist.yaml"; }

    static void set_lifetime(Config& c, Duration lifetime, Duration grace) {
        c.limits.session_lifetime = lifetime;
        c.limits.session_jitter = 0;
        c.limits.renegotiation_grace = grace;
        c.limits.idle_timeout = 30s;
        c.limits.handshake_timeout = 2s;
        c.limits.shutdown_timeout = 1s;
    }

    Config server_config(std::uint16_t destination_port, PortKind kind = PortKind::tls, Duration lifetime = 1h,
                         Duration grace = 30s) {
        Config c;
        c.mode = Mode::server;
        c.ports[kind].listen = Endpoint{"127.0.0.1", 0};
        c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
        c.credentials = Credentials{server_pki().string()};
        c.whitelist = WhitelistRef{whitelist().string()};
        set_lifetime(c, lifetime, grace);
        return c;
    }

    Config client_config(std::uint16_t server_port, PortKind kind = PortKind::tls, Duration lifetime = 1h,
                         Duration grace = 30s) {
        Config c;
        c.mode = Mode::client;
        c.ports[kind] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", server_port}, "relay.test"};
        if (kind != PortKind::plain) c.credentials = Credentials{client_pki().string()};
        set_lifetime(c, lifetime, grace);
        return c;
    }

    static relay::ServiceOptions fast_watch() {
        relay::ServiceOptions o{false, 2};
        o.watch_interval = 50ms;
        return o;
    }

    RawTlsClient raw_client(std::uint16_t port) {
        return RawTlsClient(port, TLS1_3_VERSION, "tlsrelay/1", h_->root.cert.get());
    }

    static Hierarchy* h_;
    TempDir dir_;
};
Hierarchy* TunnelTest::h_ = nullptr;

bool works(TestClient& app, const std::string& data) {
    app.write(data);
    return app.read_exactly(data.size(), 3s) == data;
}

// Flux continu dans les deux sens (via l'écho) : chaque bloc est écrit sans
// attendre l'écho des précédents, des données sont donc toujours en transit
// pendant chunks × pause.
// Un seul thread utilise la socket de test.
void stream_through(TestClient& app, std::size_t chunks, std::size_t chunk_size, std::chrono::milliseconds pause,
                    std::string& sent, std::string& received) {
    sent = make_random_data(chunks * chunk_size, 99);
    received.clear();
    const auto deadline = Clock::now() + 20s;
    std::size_t written = 0;
    auto next_write = Clock::now();  // un bloc toutes les pause
    while (received.size() < sent.size() && Clock::now() < deadline) {
        if (written < chunks && Clock::now() >= next_write) {
            app.write(sent.substr(written++ * chunk_size, chunk_size));
            next_write += pause;
        }
        auto [ec, data] = app.read_some(256 * 1024, written < chunks ? next_write : Clock::now() + 200ms);
        received += data;
        if (ec && ec != asio::error::timed_out) break;
    }
}

// Jeton de reprise calculé indépendamment de tlsrelay, d'après SPEC §4.5.
tlsrelay::tunnel::Token token_of(RawTlsClient& raw, const tlsrelay::tunnel::SessionId& session, std::uint32_t n) {
    std::uint8_t context[20];
    std::copy(session.begin(), session.end(), context);
    for (int i = 0; i < 4; ++i) context[16 + i] = static_cast<std::uint8_t>(n >> (24 - 8 * i));
    tlsrelay::tunnel::Token token{};
    const std::string label = "EXPORTER-tlsrelay-resume";
    EXPECT_EQ(SSL_export_keying_material(raw.ssl(), token.data(), token.size(), label.data(), label.size(), context,
                                         sizeof context, 1),
              1);
    return token;
}

std::optional<tlsrelay::tunnel::Frame> resume(RawTlsClient& raw, TunnelProbe& probe,
                                              const tlsrelay::tunnel::SessionId& session,
                                              const tlsrelay::tunnel::Token& token, std::uint64_t last_rx) {
    if (!raw.write(tlsrelay::tunnel::encode_resume({session, token, last_rx}))) return std::nullopt;
    return probe.next();
}

}  // namespace

TEST_F(TunnelTest, RenegotiationIsTransparentUnderLoad) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls, 100ms, 2s));
    RunningService client(client_config(server.port(PortKind::tls), PortKind::tls, 100ms, 2s));

    TestClient app(client.port(PortKind::tls));
    std::string sent, received;
    stream_through(app, 80, 32 * 1024, 30ms, sent, received);  // ~2,5 s, soit ~20 renégociations
    ASSERT_EQ(received.size(), sent.size());
    EXPECT_EQ(sha256(received), sha256(sent));

    EXPECT_GE(client.stats().renegotiations.load(), 10u);
    EXPECT_TRUE(eventually([&] { return server.stats().renegotiations.load() == client.stats().renegotiations.load(); }));
    EXPECT_EQ(client.stats().resume_failures.load(), 0u);
    EXPECT_EQ(server.stats().resume_failures.load(), 0u);
    EXPECT_EQ(server.stats().channels_opened.load(), 1u);  // un seul canal de bout en bout
    EXPECT_EQ(echo.accepted(), 1);                          // une seule connexion à la destination
    EXPECT_EQ(server.stats().protocol_errors.load(), 0u);
}

TEST_F(TunnelTest, RenegotiationMovesOpenChannelToNewGeneration) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::mtls, 300ms, 2s), fast_watch());
    RunningService client(client_config(server.port(PortKind::mtls), PortKind::mtls, 300ms, 2s), fast_watch());
    auto& srv = server.service();
    auto& cli = client.service();

    TestClient app(client.port(PortKind::mtls));
    ASSERT_TRUE(works(app, "v1"));

    write_generation(server_pki(), "v2", server_files(*h_));
    write_generation(client_pki(), "v2", client_files(*h_));
    ASSERT_TRUE(eventually([&] { return srv.current_generation() == "v2" && cli.current_generation() == "v2"; }));

    // À la renégociation suivante, le canal passe sur v2 : v1 est libérée des deux côtés.
    EXPECT_TRUE(eventually([&] { return srv.live_generations() == std::vector<std::string>{"v2"}; }));
    EXPECT_TRUE(eventually([&] { return cli.live_generations() == std::vector<std::string>{"v2"}; }));
    EXPECT_TRUE(works(app, "toujours ouvert, sur v2"));
    EXPECT_EQ(server.stats().channels_closed.load(), 0u);
}

TEST_F(TunnelTest, SessionResumesAfterTransportLoss) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls, 1h, 5s));
    CutProxy proxy(server.port(PortKind::tls));
    RunningService client(client_config(proxy.port(), PortKind::tls, 1h, 5s));

    TestClient app(client.port(PortKind::tls));
    ASSERT_TRUE(works(app, "avant"));

    std::string sent, received;
    std::thread cutter([&] {
        std::this_thread::sleep_for(300ms);
        proxy.cut();  // en plein transfert
    });
    stream_through(app, 40, 64 * 1024, 15ms, sent, received);
    cutter.join();
    ASSERT_EQ(received.size(), sent.size());
    EXPECT_EQ(sha256(received), sha256(sent));
    EXPECT_EQ(proxy.connections(), 2);
    EXPECT_EQ(client.stats().renegotiations.load(), 1u);
    EXPECT_EQ(server.stats().renegotiations.load(), 1u);
    EXPECT_EQ(echo.accepted(), 1);
}

TEST_F(TunnelTest, PlainTransportLossClosesChannel) {
    EchoServer echo;
    auto server_cfg = server_config(echo.port(), PortKind::plain);
    server_cfg.credentials.reset();
    RunningService server(std::move(server_cfg));
    CutProxy proxy(server.port(PortKind::plain));
    RunningService client(client_config(proxy.port(), PortKind::plain));

    TestClient app(client.port(PortKind::plain));
    ASSERT_TRUE(works(app, "clair"));
    proxy.cut();  // port 1 : pas de reprise possible sans TLS
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    EXPECT_EQ(proxy.connections(), 1);
}

TEST_F(TunnelTest, ServerClosesSessionThatIsNotRenegotiated) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls, 200ms, 200ms));

    auto raw = raw_client(server.port(PortKind::tls));
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    ASSERT_TRUE(probe.open(PortKind::tls));
    const auto start = Clock::now();
    std::optional<tlsrelay::tunnel::Frame> frame;
    do {
        frame = probe.next();
    } while (frame && frame->type != FrameType::close);
    ASSERT_TRUE(frame);
    EXPECT_EQ(tlsrelay::tunnel::read_status(*frame).code, static_cast<std::uint16_t>(CloseCode::lifetime_exceeded));
    EXPECT_GE(Clock::now() - start, 350ms);
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
}

TEST_F(TunnelTest, ResumeTokenIsBoundToConnectionAndSingleUse) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    const auto port = server.port(PortKind::tls);

    auto first = raw_client(port);
    ASSERT_TRUE(first.handshake());
    TunnelProbe first_probe(first);
    ASSERT_TRUE(first_probe.open(PortKind::tls));
    const auto session = first_probe.session();
    const auto token = token_of(first, session, 1);

    {  // Jeton faux : refusé, la session continue sur la première connexion.
        auto raw = raw_client(port);
        ASSERT_TRUE(raw.handshake());
        TunnelProbe probe(raw);
        auto wrong = token;
        wrong[0] ^= 1;
        const auto f = resume(raw, probe, session, wrong, 0);
        ASSERT_TRUE(f);
        EXPECT_EQ(f->type, FrameType::resume_fail);
    }
    ASSERT_TRUE(first_probe.send("abc"));
    ASSERT_EQ(first_probe.receive(3), "abc");

    auto second = raw_client(port);
    ASSERT_TRUE(second.handshake());
    TunnelProbe second_probe(second);
    const auto f = resume(second, second_probe, session, token, 0);
    ASSERT_TRUE(f);
    ASSERT_EQ(f->type, FrameType::resumed);
    // L'écho de « abc » n'a pas été acquitté : le serveur le renvoie sur la nouvelle connexion.
    EXPECT_EQ(second_probe.receive(3), "abc");
    EXPECT_TRUE(first_probe.closed());  // l'ancienne connexion est fermée par le serveur

    {  // Rejeu du même jeton : refusé.
        auto raw = raw_client(port);
        ASSERT_TRUE(raw.handshake());
        TunnelProbe probe(raw);
        const auto replay = resume(raw, probe, session, token, 0);
        ASSERT_TRUE(replay);
        EXPECT_EQ(replay->type, FrameType::resume_fail);
    }
    {  // Session inconnue : refusée.
        auto raw = raw_client(port);
        ASSERT_TRUE(raw.handshake());
        TunnelProbe probe(raw);
        auto unknown = session;
        unknown[0] ^= 1;
        const auto r = resume(raw, probe, unknown, token, 0);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->type, FrameType::resume_fail);
    }
    EXPECT_EQ(server.stats().renegotiations.load(), 1u);
    EXPECT_EQ(server.stats().resume_failures.load(), 3u);
    EXPECT_EQ(echo.accepted(), 1);
}

TEST_F(TunnelTest, ServerWaitsForResumeOnlyDuringGrace) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls, 1h, 400ms));
    {
        auto raw = raw_client(server.port(PortKind::tls));
        ASSERT_TRUE(raw.handshake());
        TunnelProbe probe(raw);
        ASSERT_TRUE(probe.open(PortKind::tls));
    }  // connexion perdue sans CLOSE
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(server.stats().channels_closed.load(), 0u);  // reprise encore possible
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    EXPECT_EQ(server.stats().resume_failures.load(), 1u);
}

TEST_F(TunnelTest, InvalidFrameClosesChannelWithProtocolError) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));

    auto raw = raw_client(server.port(PortKind::tls));
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    ASSERT_TRUE(probe.open(PortKind::tls));
    ASSERT_TRUE(raw.write(std::string("\x7f\0\0\0\0\0\0\0", 8)));  // type inconnu
    std::optional<tlsrelay::tunnel::Frame> frame;
    do {
        frame = probe.next();
    } while (frame && frame->type != FrameType::close);
    ASSERT_TRUE(frame);
    EXPECT_EQ(tlsrelay::tunnel::read_status(*frame).code, static_cast<std::uint16_t>(CloseCode::protocol_error));
    EXPECT_EQ(server.stats().protocol_errors.load(), 1u);
}

TEST_F(TunnelTest, OpenIsRefusedForAnotherPortOrDuplicateSession) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    const auto port = server.port(PortKind::tls);

    auto raw = raw_client(port);
    ASSERT_TRUE(raw.handshake());
    TunnelProbe probe(raw);
    auto f = probe.open_frame(PortKind::mtls);  // annonce le port mtls sur le port tls
    ASSERT_TRUE(f);
    EXPECT_EQ(f->type, FrameType::open_fail);

    auto first = raw_client(port);
    ASSERT_TRUE(first.handshake());
    TunnelProbe first_probe(first);
    ASSERT_TRUE(first_probe.open(PortKind::tls));
    auto second = raw_client(port);
    ASSERT_TRUE(second.handshake());
    TunnelProbe second_probe(second);
    f = second_probe.open_frame(PortKind::tls, first_probe.session());
    ASSERT_TRUE(f);
    EXPECT_EQ(f->type, FrameType::open_fail);
    EXPECT_EQ(echo.accepted(), 1);
}

TEST_F(TunnelTest, SmallResumeBufferAppliesBackpressureWithoutLoss) {
    EchoServer echo;
    auto server_cfg = server_config(echo.port());
    server_cfg.limits.resume_buffer = 64 * 1024;
    RunningService server(std::move(server_cfg));
    auto client_cfg = client_config(server.port(PortKind::tls));
    client_cfg.limits.resume_buffer = 64 * 1024;
    RunningService client(std::move(client_cfg));

    TestClient app(client.port(PortKind::tls));
    std::string sent;
    const auto received = exchange(app, 4 << 20, 5, &sent);
    ASSERT_EQ(received.size(), sent.size());
    EXPECT_EQ(sha256(received), sha256(sent));
}

TEST_F(TunnelTest, SilentTransportIsDetectedByKeepaliveAndResumed) {
    EchoServer echo;
    auto server_cfg = server_config(echo.port(), PortKind::tls, 1h, 5s);
    server_cfg.limits.keepalive_interval = 200ms;
    RunningService server(std::move(server_cfg));
    CutProxy proxy(server.port(PortKind::tls));
    auto client_cfg = client_config(proxy.port(), PortKind::tls, 1h, 5s);
    client_cfg.limits.keepalive_interval = 200ms;
    RunningService client(std::move(client_cfg));

    TestClient app(client.port(PortKind::tls));
    ASSERT_TRUE(works(app, "avant"));
    proxy.freeze();  // plus rien ne passe, sans aucune erreur TCP
    const auto start = Clock::now();
    EXPECT_TRUE(works(app, "après le gel du lien"));
    EXPECT_GE(Clock::now() - start, 400ms);  // détection : 3 intervalles de silence
    EXPECT_EQ(client.stats().renegotiations.load(), 1u);
    EXPECT_EQ(proxy.connections(), 2);
    EXPECT_EQ(echo.accepted(), 1);
}

TEST_F(TunnelTest, SilentPlainTransportClosesChannel) {
    EchoServer echo;
    auto server_cfg = server_config(echo.port(), PortKind::plain);
    server_cfg.credentials.reset();
    server_cfg.limits.keepalive_interval = 200ms;
    RunningService server(std::move(server_cfg));
    CutProxy proxy(server.port(PortKind::plain));
    auto client_cfg = client_config(proxy.port(), PortKind::plain);
    client_cfg.limits.keepalive_interval = 200ms;
    RunningService client(std::move(client_cfg));

    TestClient app(client.port(PortKind::plain));
    ASSERT_TRUE(works(app, "clair"));
    proxy.freeze();
    EXPECT_TRUE(app.wait_closed(3s));
    EXPECT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
}

TEST_F(TunnelTest, KeepaliveToleratesApplicationNotReading) {
    EchoServer echo;
    auto server_cfg = server_config(echo.port(), PortKind::tls, 1h, 5s);
    server_cfg.limits.keepalive_interval = 200ms;
    RunningService server(std::move(server_cfg));
    auto client_cfg = client_config(server.port(PortKind::tls), PortKind::tls, 1h, 5s);
    client_cfg.limits.keepalive_interval = 200ms;
    RunningService client(std::move(client_cfg));

    TestClient app(client.port(PortKind::tls));
    // Assez de données pour saturer les tampons TCP, quelle que soit leur taille
    // (Windows : petits tampons ; Linux : tampons de loopback plus grands).
    const auto data = make_random_data(3 << 20, 11);
    app.write(data);
    std::this_thread::sleep_for(1500ms);  // l'application ne lit pas : contre-pression jusqu'à la destination
    const auto received = app.read_exactly(data.size(), 10s);
    EXPECT_EQ(sha256(received), sha256(data));
    EXPECT_EQ(client.stats().renegotiations.load(), 0u);  // aucune fausse détection
    EXPECT_EQ(server.stats().resume_failures.load(), 0u);
}

TEST_F(TunnelTest, TransportLossBeforeOpenOkReopensTunnel) {
    // Le serveur cherche encore à joindre la destination quand le lien est coupé.
    ReservedPort reserved;
    auto server_cfg = server_config(reserved.port(), PortKind::tls);
    server_cfg.destination->dial_timeout = 100ms;
    server_cfg.destination->dial_retries = 3;
    server_cfg.destination->dial_backoff = 400ms;
    RunningService server(std::move(server_cfg));
    CutProxy proxy(server.port(PortKind::tls));
    RunningService client(client_config(proxy.port(), PortKind::tls));

    TestClient app(client.port(PortKind::tls));
    app.write("en attente");  // gardé par le client jusqu'à OPEN_OK
    std::this_thread::sleep_for(250ms);
    proxy.cut();
    EchoServer echo(reserved);  // la destination devient joignable

    EXPECT_EQ(app.read_exactly(10, 5s), "en attente");
    EXPECT_EQ(proxy.connections(), 2);
    EXPECT_EQ(client.stats().channels_opened.load(), 1u);
    EXPECT_EQ(echo.accepted(), 1);  // une seule connexion à la destination aboutie
}
