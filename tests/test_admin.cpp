// Canal d'administration et cycle de vie (phase 6, SPEC §10) : commandes,
// verrou d'instance, arrêt avec drain, arrêt immédiat, rechargement,
// journalisation à chaud, métriques.

#include "tlsrelay/admin/admin.hpp"
#include "tlsrelay/logging.hpp"

#include "support/net_helpers.hpp"
#include "support/test_pki.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <random>
#include <sstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace testnet;
using testpki::TempDir;

namespace {

class AdminTest : public ::testing::Test {
protected:
    void SetUp() override {
#ifdef _WIN32
        std::mt19937 engine{std::random_device{}()};
        endpoint_ = "\\\\.\\pipe\\tlsrelay-test-" + std::to_string(engine());
#else
        endpoint_ = (dir_.path() / "admin.sock").string();
#endif
        std::ofstream(whitelist()) << "peers:\n  - { name: poste, ip: 127.0.0.1, ports: [plain] }\n";
    }

    std::filesystem::path whitelist() const { return dir_.path() / "whitelist.yaml"; }

    Config server_config(std::uint16_t destination_port) {
        Config c;
        c.mode = Mode::server;
        c.instance = "essai";
        c.ports[PortKind::plain].listen = Endpoint{"127.0.0.1", 0};
        c.destination = Destination{Endpoint{"127.0.0.1", destination_port}};
        c.whitelist = WhitelistRef{whitelist().string()};
        c.admin.endpoint = endpoint_;
        c.limits.shutdown_timeout = 5s;
        return c;
    }

    static Config client_config(std::uint16_t upstream) {
        Config c;
        c.mode = Mode::client;
        c.ports[PortKind::plain] = PortConfig{Endpoint{"127.0.0.1", 0}, Endpoint{"127.0.0.1", upstream}, {}};
        return c;
    }

    admin::CallResult call(const std::string& request) { return admin::call(endpoint_, request, 5s); }

    // Corps de la réponse ; échec du test si la commande échoue.
    std::string ok(const std::string& request) {
        const auto r = call(request);
        EXPECT_TRUE(r.reply) << request << " : " << r.error;
        if (!r.reply) return {};
        EXPECT_TRUE(r.reply->ok) << request << " : " << r.reply->body;
        return r.reply->body;
    }

    TempDir dir_;
    std::string endpoint_;
};

bool contains(const std::string& text, const std::string& fragment) { return text.find(fragment) != std::string::npos; }

}  // namespace

TEST(AdminProtocol, ParsesRequestWords) {
    const auto r = admin::parse_request("reload  --kill-old\r\n");
    ASSERT_TRUE(r);
    EXPECT_EQ(r->command, "reload");
    EXPECT_EQ(r->args, std::vector<std::string>{"--kill-old"});
    EXPECT_FALSE(admin::parse_request("   \n"));
    EXPECT_FALSE(admin::parse_request(std::string("status\x01", 7)));
    EXPECT_EQ(admin::encode_reply({true, "abc"}), "OK 3\nabc");
    EXPECT_EQ(admin::encode_reply({false, ""}), "ERREUR 0\n");
}

TEST_F(AdminTest, StatusDescribesInstance) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    const auto body = ok("status");
    EXPECT_TRUE(contains(body, "instance : essai")) << body;
    EXPECT_TRUE(contains(body, "mode : server")) << body;
    EXPECT_TRUE(contains(body, "OpenSSL 3.")) << body;
    EXPECT_TRUE(contains(body, "port plain : 127.0.0.1:" + std::to_string(server.port()))) << body;
    EXPECT_TRUE(contains(body, "liste blanche : 1 pair(s)")) << body;
    EXPECT_EQ(ok("ping"), "pong\n");
}

TEST_F(AdminTest, UnknownOrMalformedCommandsAreRefused) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    auto r = call("format c:");
    ASSERT_TRUE(r.reply) << r.error;
    EXPECT_FALSE(r.reply->ok);
    EXPECT_TRUE(contains(r.reply->body, "commandes :")) << r.reply->body;

    r = call("stop maintenant");
    ASSERT_TRUE(r.reply) << r.error;
    EXPECT_FALSE(r.reply->ok);

    r = call(std::string(admin::kMaxRequest + 10, 'x'));
    ASSERT_TRUE(r.reply) << r.error;
    EXPECT_FALSE(r.reply->ok);
    EXPECT_TRUE(contains(r.reply->body, "trop longue")) << r.reply->body;
    EXPECT_FALSE(server.service().stats().channels_opened.load());
}

TEST_F(AdminTest, SecondExecutionOfSameInstanceIsRefused) {
    EchoServer echo;
    {
        RunningService first(server_config(echo.port()));
        EXPECT_THROW(relay::Service second(server_config(echo.port())), admin::AlreadyRunning);
        ok("ping");  // la première exécution n'est pas affectée
    }
    // Verrou libéré à l'arrêt : une nouvelle exécution démarre.
    RunningService again(server_config(echo.port()));
    EXPECT_EQ(ok("ping"), "pong\n");
}

TEST_F(AdminTest, UnreachableInstanceIsReported) {
    const auto r = call("status");
    EXPECT_FALSE(r.reply);
    EXPECT_TRUE(r.unreachable) << r.error;
}

#ifndef _WIN32
TEST_F(AdminTest, SocketIsRestrictedToOwnerAndGroup) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    struct stat st {};
    ASSERT_EQ(::stat(endpoint_.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0660u);
    server.stop();
    EXPECT_FALSE(std::filesystem::exists(endpoint_));  // supprimé à l'arrêt
}
#endif

TEST_F(AdminTest, StopDrainsThenStops) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port()));
    TestClient app(client.port());
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    const auto start = Clock::now();
    const auto body = ok("stop 300ms");
    EXPECT_TRUE(contains(body, "drain de 1 canal(aux)")) << body;
    EXPECT_TRUE(server.wait_finished(5s));
    EXPECT_GE(Clock::now() - start, 250ms);  // le canal ouvert a eu son délai de drain
    EXPECT_TRUE(app.wait_closed(2s));
    EXPECT_TRUE(call("ping").unreachable);
}

TEST_F(AdminTest, KillStopsImmediately) {
    EchoServer echo;
    auto cfg = server_config(echo.port());
    cfg.limits.shutdown_timeout = 30s;
    RunningService server(std::move(cfg));
    RunningService client(client_config(server.port()));
    TestClient app(client.port());
    app.write("a");
    ASSERT_EQ(app.read_exactly(1), "a");

    const auto start = Clock::now();
    ok("kill");
    EXPECT_TRUE(server.wait_finished(3s));
    EXPECT_LT(Clock::now() - start, 3s);
    EXPECT_TRUE(app.wait_closed(2s));
}

TEST_F(AdminTest, ChannelsListsOpenChannels) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port()));
    TestClient app(client.port());
    app.write("abc");
    ASSERT_EQ(app.read_exactly(3), "abc");

    const auto body = ok("channels");
    EXPECT_TRUE(contains(body, "1 canal(aux)")) << body;
    EXPECT_TRUE(contains(body, "port=plain état=ouvert")) << body;
    EXPECT_TRUE(contains(body, "pair=« poste »")) << body;
    EXPECT_TRUE(contains(body, "montant=3o")) << body;
}

TEST_F(AdminTest, MetricsUsePrometheusTextFormat) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    RunningService client(client_config(server.port()));
    {
        TestClient app(client.port());
        app.write("x");
        ASSERT_EQ(app.read_exactly(1), "x");
    }
    ASSERT_TRUE(eventually([&] { return server.stats().channels_closed.load() == 1; }));
    const auto body = ok("metrics");
    EXPECT_TRUE(contains(body, "# TYPE tlsrelay_channels_opened_total counter\n")) << body;
    EXPECT_TRUE(contains(body, "tlsrelay_channels_opened_total{instance=\"essai\"} 1\n")) << body;
    EXPECT_TRUE(contains(body, "tlsrelay_channels_active{instance=\"essai\",port=\"plain\"} 0\n")) << body;
    EXPECT_TRUE(contains(body, "tlsrelay_info{instance=\"essai\",mode=\"server\"")) << body;
    // Une ligne par échantillon : nom{étiquettes} valeur.
    std::istringstream lines(body);
    for (std::string line; std::getline(lines, line);) {
        if (line.empty() || line[0] == '#') continue;
        EXPECT_NE(line.find("} "), std::string::npos) << line;
    }
}

TEST_F(AdminTest, ReloadReportsWhatChanged) {
    EchoServer echo;
    const auto config_path = dir_.path() / "serveur.yaml";
    auto write_config = [&](const std::string& level, std::uint16_t dest_port) {
        std::ofstream(config_path) << "mode: server\ninstance: essai\nlogging: { level: " << level << " }\n"
                                   << "whitelist: { file: \"" << whitelist().generic_string() << "\" }\n"
                                   << "destination: { address: 127.0.0.1, port: " << dest_port << " }\n"
                                   << "admin: { endpoint: '" << endpoint_ << "' }\n"
                                   << "ports:\n  plain: { listen: \"127.0.0.1:9\" }\n";
    };
    write_config("info", echo.port());
    auto loaded = load_config_file(config_path);
    ASSERT_TRUE(loaded.config) << (loaded.errors.empty() ? "" : loaded.errors[0].message);
    loaded.config->ports[PortKind::plain].listen.port = 0;  // port libre choisi par le système
    relay::ServiceOptions options{false, 2};
    options.config_path = config_path.string();
    RunningService server(*loaded.config, options);

    std::ofstream(whitelist()) << "peers:\n  - { name: a, ip: 127.0.0.1 }\n  - { name: b, ip: 10.0.0.0/8 }\n";
    write_config("debug", static_cast<std::uint16_t>(echo.port() + 1));
    const auto body = ok("reload");
    EXPECT_TRUE(contains(body, "liste blanche : 2 pair(s)")) << body;
    EXPECT_TRUE(contains(body, "redémarrage nécessaire pour appliquer")) << body;
    EXPECT_TRUE(contains(body, "destination\n")) << body;
    EXPECT_EQ(logging::level(logging::Category::activity), LogLevel::debug);
    logging::init_default();
}

TEST_F(AdminTest, LogLevelChangesAtRuntime) {
    EchoServer echo;
    RunningService server(server_config(echo.port()));
    EXPECT_EQ(ok("log-level activity=trace"), "niveaux : activity=trace config=info\n");
    EXPECT_EQ(logging::level(logging::Category::activity), LogLevel::trace);
    EXPECT_EQ(ok("log-level error"), "niveaux : activity=error config=error\n");
    const auto r = call("log-level bavard");
    ASSERT_TRUE(r.reply);
    EXPECT_FALSE(r.reply->ok);
    logging::init_default();
}

#ifndef _WIN32  // sous Windows, un fichier ouvert ne peut pas être renommé
TEST_F(AdminTest, LogReopenStartsNewFileAfterRotation) {
    const auto log = dir_.path() / "tlsrelay.log";
    LogConfig lc;
    lc.output = log.string();
    logging::init(lc);
    {
        EchoServer echo;
        RunningService server(server_config(echo.port()));
        std::filesystem::rename(log, dir_.path() / "tlsrelay.log.1");  // rotation externe
        EXPECT_TRUE(contains(ok("log-reopen"), "fichier de log rouvert"));
        EXPECT_TRUE(std::filesystem::exists(log));
        logging::config().info("après rotation");
    }
    logging::init_default();  // ferme le fichier
    std::ifstream in(log);
    const std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(contains(content, "après rotation")) << content;
    EXPECT_FALSE(contains(content, "service démarré")) << "écrit avant la rotation";
}
#endif
