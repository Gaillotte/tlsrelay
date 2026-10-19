// Live PKI rotation (phase 4, SPEC §7.4 and §7.5): new
// connections move to the new generation, open connections
// finish on the old one, which is released when it has no connection left.

#include "support/net_helpers.hpp"
#include "support/raw_tls_client.hpp"
#include "support/test_pki.hpp"

#include <gtest/gtest.h>

#include <csignal>
#include <fstream>

using namespace testnet;
using namespace testpki;

namespace {

constexpr const char* kClientSubject = "CN=client.test,O=tlsrelay-test";

std::string pems(std::initializer_list<const X509*> certs) {
    std::string out;
    for (const X509* c : certs) out += pem(c);
    return out;
}

// Generation of a server tlsrelay: identity, trust roots, expected Clients CAs.
GenerationFiles server_generation(const Issued& leaf, const Issued& ca, std::initializer_list<const X509*> roots,
                                  std::initializer_list<const X509*> client_cas) {
    return {pem(leaf.key.get()), pem(leaf.cert.get()), pem(ca.cert.get()), pems(roots), pems(client_cas)};
}

// Generation of a client tlsrelay: identity, trust roots, expected Servers CAs.
GenerationFiles client_generation(const Issued& leaf, const Issued& ca, std::initializer_list<const X509*> roots,
                                  std::initializer_list<const X509*> server_cas) {
    return {pem(leaf.key.get()), pem(leaf.cert.get()), pem(ca.cert.get()), pems(roots), pems(server_cas)};
}

bool same_cert(const X509* a, const X509* b) { return a && b && X509_cmp(a, b) == 0; }

class RotationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        a_ = new Hierarchy(Hierarchy::create("A"));
        b_ = new Hierarchy(Hierarchy::create("B"));
    }
    static void TearDownTestSuite() {
        delete a_;
        delete b_;
    }

    void SetUp() override {
        write_generation(server_pki(), "v1", server_files(*a_));
        write_generation(client_pki(), "v1", client_files(*a_));
        std::ofstream(whitelist()) << "peers:\n  - { name: workstation, ip: 127.0.0.1, ports: [tls, mtls], subject: \""
                                   << kClientSubject << "\" }\n";
    }

    std::filesystem::path server_pki() const { return dir_ / "server"; }
    std::filesystem::path client_pki() const { return dir_ / "client"; }
    std::filesystem::path whitelist() const { return dir_ / "whitelist.yaml"; }

    Config server_config(std::uint16_t destination_port, PortKind kind = PortKind::tls) {
        Config c;
        c.mode = Mode::server;
        c.ports[kind].listen = Endpoint{"127.0.0.1", 0};
        c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
        c.credentials = Credentials{server_pki().string()};
        c.whitelist = WhitelistRef{whitelist().string()};
        c.limits.shutdown_timeout = 1s;
        return c;
    }

    Config client_config(std::uint16_t server_port, PortKind kind = PortKind::mtls) {
        Config c;
        c.mode = Mode::client;
        c.ports[kind] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", server_port}, "relay.test"};
        c.credentials = Credentials{client_pki().string()};
        c.limits.shutdown_timeout = 1s;
        return c;
    }

    static relay::ServiceOptions fast_watch() {
        relay::ServiceOptions o{false, 2};
        o.watch_interval = 50ms;
        return o;
    }

    static Hierarchy* a_;
    static Hierarchy* b_;
    TempDir dir_;
};
Hierarchy* RotationTest::a_ = nullptr;
Hierarchy* RotationTest::b_ = nullptr;

bool works(TestClient& app, const std::string& data) {
    app.write(data);
    return app.read_exactly(data.size(), 3s) == data;
}

bool works(TunnelProbe& tunnel, const std::string& data) {
    return tunnel.send(data) && tunnel.receive(data.size()) == data;
}

}  // namespace

TEST_F(RotationTest, NewConnectionsUseNewGenerationWhileOldOnesDrain) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_watch());
    auto& service = server.service();
    EXPECT_EQ(service.current_generation(), "v1");

    RawTlsClient before(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", a_->root.cert.get());
    ASSERT_TRUE(before.handshake());
    TunnelProbe before_tunnel(before);
    ASSERT_TRUE(before_tunnel.open(PortKind::tls));
    EXPECT_TRUE(same_cert(SSL_get0_peer_certificate(before.ssl()), a_->server.cert.get()));
    ASSERT_TRUE(works(before_tunnel, "v1"));

    // New certificate (new key pair), same CA.
    auto renewed = make_certificate({.common_name = "relay.test", .usage = Usage::server, .dns = {"relay.test"}},
                                    &a_->servers_ca);
    write_generation(server_pki(), "v2", server_generation(renewed, a_->servers_ca, {a_->root.cert.get()},
                                                           {a_->clients_ca.cert.get()}));
    ASSERT_TRUE(eventually([&] { return service.current_generation() == "v2"; }));

    RawTlsClient after(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", a_->root.cert.get());
    ASSERT_TRUE(after.handshake());
    TunnelProbe after_tunnel(after);
    ASSERT_TRUE(after_tunnel.open(PortKind::tls));
    EXPECT_TRUE(same_cert(SSL_get0_peer_certificate(after.ssl()), renewed.cert.get()));
    EXPECT_TRUE(works(after_tunnel, "v2"));

    // The connection opened before the switch continues on the old generation.
    EXPECT_TRUE(works(before_tunnel, "still v1"));
    EXPECT_EQ(service.live_generations(), (std::vector<std::string>{"v2", "v1"}));
    EXPECT_EQ(server.stats().pki_rotations.load(), 1u);
}

TEST_F(RotationTest, OldGenerationIsReleasedWhenItsLastConnectionCloses) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_watch());
    auto& service = server.service();
    {
        RawTlsClient before(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", a_->root.cert.get());
        ASSERT_TRUE(before.handshake());
        TunnelProbe before_tunnel(before);
        ASSERT_TRUE(before_tunnel.open(PortKind::tls));
        ASSERT_TRUE(works(before_tunnel, "v1"));
        write_generation(server_pki(), "v2", server_files(*a_));
        ASSERT_TRUE(eventually([&] { return service.current_generation() == "v2"; }));
        EXPECT_EQ(service.live_generations().size(), 2u);
        // Closing the channel: without CLOSE, the server would wait for a session resumption.
        ASSERT_TRUE(before_tunnel.close());
    }  // closing of the last connection of v1
    EXPECT_TRUE(eventually([&] { return service.live_generations() == std::vector<std::string>{"v2"}; }));
}

TEST_F(RotationTest, InvalidGenerationIsRefusedAndServiceContinues) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_watch());
    auto& service = server.service();

    auto broken = server_files(*a_);
    broken.key = pem(a_->client.key.get());  // the key does not match the certificate
    write_generation(server_pki(), "v2", broken);
    ASSERT_TRUE(eventually([&] { return server.stats().pki_reload_failures.load() == 1; }));
    EXPECT_EQ(service.current_generation(), "v1");

    RawTlsClient raw(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", a_->root.cert.get());
    ASSERT_TRUE(raw.handshake());
    TunnelProbe raw_tunnel(raw);
    ASSERT_TRUE(raw_tunnel.open(PortKind::tls));
    EXPECT_TRUE(works(raw_tunnel, "service maintained"));
}

TEST_F(RotationTest, GuardRefusesRootChangeWithoutPreTrust) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::mtls), fast_watch());
    auto& service = server.service();

    // Direct move from root A to root B: clients on A would be cut off.
    write_generation(server_pki(), "v2", server_files(*b_));
    ASSERT_TRUE(eventually([&] { return server.stats().pki_reload_failures.load() == 1; }));
    EXPECT_EQ(service.current_generation(), "v1");
}

TEST_F(RotationTest, GuardRefusesIdentityFromUnknownRootEvenWithoutMtls) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::tls), fast_watch());
    auto& service = server.service();

    // TLS-only server: its roots are not used to verify the clients,
    // but a certificate from root B would cut off the clients that only
    // know A.
    write_generation(server_pki(), "v2", server_files(*b_));
    ASSERT_TRUE(eventually([&] { return server.stats().pki_reload_failures.load() == 1; }));
    EXPECT_EQ(service.current_generation(), "v1");
}

TEST_F(RotationTest, KillOldClosesConnectionsOfRetiredGeneration) {
    EchoServer echo;
    RunningService server(server_config(echo.port()), fast_watch());
    auto& service = server.service();

    RawTlsClient before(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", a_->root.cert.get());
    ASSERT_TRUE(before.handshake());
    TunnelProbe before_tunnel(before);
    ASSERT_TRUE(before_tunnel.open(PortKind::tls));
    ASSERT_TRUE(works(before_tunnel, "v1"));
    write_generation(server_pki(), "v2", server_files(*a_));
    ASSERT_TRUE(eventually([&] { return service.current_generation() == "v2"; }));
    RawTlsClient after(server.port(PortKind::tls), TLS1_3_VERSION, "tlsrelay/1", a_->root.cert.get());
    ASSERT_TRUE(after.handshake());
    TunnelProbe after_tunnel(after);
    ASSERT_TRUE(after_tunnel.open(PortKind::tls));
    ASSERT_TRUE(works(after_tunnel, "v2"));

    service.reload(true);  // emergency revocation of the old generation
    EXPECT_TRUE(before_tunnel.closed());
    EXPECT_TRUE(works(after_tunnel, "still open"));
    EXPECT_TRUE(eventually([&] { return service.live_generations() == std::vector<std::string>{"v2"}; }));
}

TEST_F(RotationTest, WatchDisabledWaitsForExplicitReload) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.credentials->watch = false;
    RunningService server(std::move(cfg), fast_watch());
    auto& service = server.service();

    write_generation(server_pki(), "v2", server_files(*a_));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(service.current_generation(), "v1");
    service.reload();
    EXPECT_TRUE(eventually([&] { return service.current_generation() == "v2"; }));
}

#ifdef SIGHUP
TEST_F(RotationTest, SighupTriggersReload) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.credentials->watch = false;
    relay::ServiceOptions options{true, 2};
    RunningService server(std::move(cfg), options);
    auto& service = server.service();
    std::this_thread::sleep_for(50ms);  // run() has started

    write_generation(server_pki(), "v2", server_files(*a_));
    std::raise(SIGHUP);
    EXPECT_TRUE(eventually([&] { return service.current_generation() == "v2"; }));
}
#endif

// Root change in 3 steps (SPEC §7.5), with mTLS, without interruption:
// at each step new connections go through, and a connection opened
// at the start stays open until the end.
TEST_F(RotationTest, ThreeStepRootChangeKeepsServiceAvailable) {
    EchoServer echo;
    RunningService server(server_config(echo.port(), PortKind::mtls), fast_watch());
    RunningService client(client_config(server.port(PortKind::mtls)), fast_watch());
    auto& srv = server.service();
    auto& cli = client.service();

    auto step = [&](const std::string& name, const GenerationFiles& server_files_,
                    const GenerationFiles& client_files_) {
        write_generation(server_pki(), name, server_files_);
        write_generation(client_pki(), name, client_files_);
        ASSERT_TRUE(eventually([&] { return srv.current_generation() == name && cli.current_generation() == name; }))
            << name << ": server=" << srv.current_generation() << " client=" << cli.current_generation();
        TestClient app(client.port(PortKind::mtls));
        EXPECT_TRUE(works(app, "step " + name)) << name;
    };

    TestClient long_lived(client.port(PortKind::mtls));
    ASSERT_TRUE(works(long_lived, "start"));

    const auto* rootA = a_->root.cert.get();
    const auto* rootB = b_->root.cert.get();
    // Step 1: pre-trust (roots A and B), identities unchanged.
    step("v2", server_generation(a_->server, a_->servers_ca, {rootA, rootB},
                                 {a_->clients_ca.cert.get(), b_->clients_ca.cert.get()}),
         client_generation(a_->client, a_->clients_ca, {rootA, rootB},
                           {a_->servers_ca.cert.get(), b_->servers_ca.cert.get()}));

    // Step 2, first on the server side only: a client still at step 1 accepts the new PKI.
    write_generation(server_pki(), "v3", server_generation(b_->server, b_->servers_ca, {rootA, rootB},
                                                           {a_->clients_ca.cert.get(), b_->clients_ca.cert.get()}));
    ASSERT_TRUE(eventually([&] { return srv.current_generation() == "v3"; }));
    {
        TestClient mixed(client.port(PortKind::mtls));
        EXPECT_TRUE(works(mixed, "server on B, client on A"));
    }
    step("v3", server_generation(b_->server, b_->servers_ca, {rootA, rootB},
                                 {a_->clients_ca.cert.get(), b_->clients_ca.cert.get()}),
         client_generation(b_->client, b_->clients_ca, {rootA, rootB},
                           {a_->servers_ca.cert.get(), b_->servers_ca.cert.get()}));

    // Step 3: removal of root A.
    step("v4", server_generation(b_->server, b_->servers_ca, {rootB}, {b_->clients_ca.cert.get()}),
         client_generation(b_->client, b_->clients_ca, {rootB}, {b_->servers_ca.cert.get()}));

    EXPECT_TRUE(works(long_lived, "still open on v1"));
    EXPECT_EQ(srv.stats().pki_reload_failures.load(), 0u);
    EXPECT_EQ(cli.stats().pki_reload_failures.load(), 0u);
}
