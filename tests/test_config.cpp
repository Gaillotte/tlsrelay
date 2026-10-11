#include "tlsrelay/config.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

using namespace tlsrelay;
using namespace std::chrono_literals;

namespace {

const char* kClient = R"(
mode: client
instance: rc-client
logging: { level: debug, format: json, output: stderr, categories: { config: trace } }
limits: { idle_timeout: 2m, session_lifetime: 30m, session_jitter: 5%, resume_buffer: 1MiB, max_channels: 100 }
source_address: 127.0.0.2
ports:
  plain: { listen: "127.0.0.1:7001", upstream: "relay.example:9001" }
  tls:   { listen: "127.0.0.1:7002", upstream: "relay.example:9002", server_name: relay.example }
credentials: { pki_root: /etc/tlsrelay/pki }
)";

const char* kServer = R"(
mode: server
destination: { address: 10.0.0.42, port: 8080, dial_retries: 3, dial_backoff: 500ms }
whitelist: { file: whitelist.yaml }
ports:
  plain: { listen: "0.0.0.0:9001" }
)";

bool has_error(const LoadResult& r, const std::string& path, const std::string& fragment = "") {
    return std::any_of(r.errors.begin(), r.errors.end(), [&](const Issue& i) {
        return i.path == path && i.message.find(fragment) != std::string::npos;
    });
}

std::string dump(const LoadResult& r) {
    std::string s;
    for (const auto& e : r.errors) s += e.path + " : " + e.message + "\n";
    return s;
}

}  // namespace

TEST(Config, LoadsValidClient) {
    const auto r = load_config_string(kClient);
    ASSERT_TRUE(r.config) << dump(r);
    const auto& c = *r.config;
    EXPECT_EQ(c.mode, Mode::client);
    EXPECT_EQ(c.instance, "rc-client");
    EXPECT_EQ(c.logging.level, LogLevel::debug);
    EXPECT_EQ(c.logging.format, LogFormat::json);
    EXPECT_EQ(c.logging.config, LogLevel::trace);
    EXPECT_FALSE(c.logging.activity.has_value());
    EXPECT_EQ(c.limits.idle_timeout, Duration(2min));
    EXPECT_EQ(c.limits.session_lifetime, Duration(30min));
    EXPECT_DOUBLE_EQ(c.limits.session_jitter, 0.05);
    EXPECT_EQ(c.limits.resume_buffer, 1u << 20);
    EXPECT_EQ(c.limits.max_channels, 100u);
    EXPECT_EQ(c.limits.shutdown_timeout, Duration(30s));  // valeur par défaut
    ASSERT_EQ(c.ports.size(), 2u);
    EXPECT_EQ(c.ports.at(PortKind::plain).listen, (Endpoint{"127.0.0.1", 7001}));
    EXPECT_EQ(c.ports.at(PortKind::tls).upstream, (Endpoint{"relay.example", 9002}));
    EXPECT_EQ(c.ports.at(PortKind::tls).server_name, "relay.example");
    EXPECT_EQ(c.source_address, "127.0.0.2");
}

TEST(Config, LoadsValidServerWithDefaults) {
    const auto r = load_config_string(kServer);
    ASSERT_TRUE(r.config) << dump(r);
    const auto& c = *r.config;
    EXPECT_EQ(c.mode, Mode::server);
    EXPECT_EQ(c.instance, "default");
    ASSERT_TRUE(c.destination);
    EXPECT_EQ(c.destination->endpoint, (Endpoint{"10.0.0.42", 8080}));
    EXPECT_EQ(c.destination->dial_timeout, Duration(5s));
    EXPECT_EQ(c.destination->dial_backoff, Duration(500));
    EXPECT_EQ(c.limits.idle_timeout, Duration(5min));
    ASSERT_TRUE(c.whitelist);
    EXPECT_EQ(c.whitelist->file, "whitelist.yaml");
}

TEST(Config, ExamplesAreValid) {
    for (const char* name : {"client.yaml", "server.yaml"}) {
        const auto r = load_config_file(std::string(TLSRELAY_EXAMPLES_DIR) + "/" + name);
        EXPECT_TRUE(r.config) << name << "\n" << dump(r);
    }
}

TEST(Config, ReportsYamlSyntaxErrorWithPosition) {
    const auto r = load_config_string("mode: client\nports: [unclosed\n");
    ASSERT_FALSE(r.config);
    ASSERT_EQ(r.errors.size(), 1u);
    EXPECT_NE(r.errors[0].path.find("ligne"), std::string::npos);
}

TEST(Config, RejectsUnknownKeysAtEveryLevel) {
    const auto r = load_config_string(R"(
mode: client
colour: blue
limits: { idle_timout: 5m }
ports:
  plain: { listen: "127.0.0.1:7001", upstream: "h:1", extra: 1 }
)");
    EXPECT_TRUE(has_error(r, "colour", "clé inconnue")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.idle_timout", "clé inconnue")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.plain.extra", "clé inconnue")) << dump(r);
}

TEST(Config, CollectsAllFormatErrors) {
    const auto r = load_config_string(R"(
mode: proxy
limits: { idle_timeout: 5 minutes, session_jitter: 10, resume_buffer: 4MB, max_channels: -1 }
logging: { level: verbose, format: xml }
ports:
  plain: { listen: "127.0.0.1", upstream: "h:1" }
)");
    EXPECT_TRUE(has_error(r, "mode")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.idle_timeout", "durée invalide")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.session_jitter", "pourcentage")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.resume_buffer", "taille")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.max_channels")) << dump(r);
    EXPECT_TRUE(has_error(r, "logging.level")) << dump(r);
    EXPECT_TRUE(has_error(r, "logging.format")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.plain.listen", "adresse invalide")) << dump(r);
    EXPECT_GE(r.errors.size(), 8u);
}

TEST(Config, RequiresModeAndListen) {
    const auto r = load_config_string("ports: { plain: { upstream: \"h:1\" } }");
    EXPECT_TRUE(has_error(r, "mode", "obligatoire")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.plain.listen", "obligatoire")) << dump(r);
}

TEST(Config, RejectsSectionWithWrongType) {
    const auto r = load_config_string("mode: client\nlimits: 5\nports: { plain: { listen: \"127.0.0.1:1\", upstream: \"h:1\" } }");
    EXPECT_TRUE(has_error(r, "limits", "section")) << dump(r);
}

TEST(Validate, ClientRules) {
    const auto r = load_config_string(R"(
mode: client
destination: { address: 10.0.0.1, port: 80 }
source_address: not-an-ip
ports:
  plain: { listen: "127.0.0.1:7001", server_name: x }
  tls:   { listen: "127.0.0.1:7002", upstream: "h:0" }
)");
    EXPECT_TRUE(has_error(r, "ports.plain.upstream", "obligatoire")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.plain.server_name", "sans objet")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.tls.upstream", "1–65535")) << dump(r);
    EXPECT_TRUE(has_error(r, "destination", "sans objet")) << dump(r);
    EXPECT_TRUE(has_error(r, "source_address")) << dump(r);
    EXPECT_TRUE(has_error(r, "credentials.pki_root", "tls")) << dump(r);
}

TEST(Validate, ServerRules) {
    const auto r = load_config_string(R"(
mode: server
source_address: 127.0.0.1
ports:
  plain: { listen: "0.0.0.0:9001", upstream: "h:1", server_name: x }
)");
    EXPECT_TRUE(has_error(r, "destination", "obligatoire")) << dump(r);
    EXPECT_TRUE(has_error(r, "whitelist", "obligatoire")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.plain.upstream", "sans objet")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.plain.server_name", "sans objet")) << dump(r);
    EXPECT_TRUE(has_error(r, "source_address", "sans objet")) << dump(r);
}

TEST(Validate, DestinationRules) {
    const auto r = load_config_string(R"(
mode: server
destination: { address: 10.0.0.1, port: 0, dial_retries: 0, dial_timeout: 0s }
ports: { plain: { listen: "0.0.0.0:9001" } }
)");
    EXPECT_TRUE(has_error(r, "destination.port")) << dump(r);
    EXPECT_TRUE(has_error(r, "destination.dial_retries")) << dump(r);
    EXPECT_TRUE(has_error(r, "destination.dial_timeout")) << dump(r);
}

TEST(Validate, ListenAddressRules) {
    const auto r = load_config_string(R"(
mode: server
destination: { address: 10.0.0.1, port: 80 }
credentials: { pki_root: pki }
ports:
  plain: { listen: "0.0.0.0:9001" }
  tls:   { listen: "127.0.0.1:9001" }
  mtls:  { listen: "relay.example:9003" }
)");
    EXPECT_TRUE(has_error(r, "ports.tls.listen", "même adresse")) << dump(r);
    EXPECT_TRUE(has_error(r, "ports.mtls.listen", "adresse IP")) << dump(r);
}

TEST(Validate, RequiresAtLeastOnePort) {
    const auto r = load_config_string("mode: client\n");
    EXPECT_TRUE(has_error(r, "ports", "aucun port")) << dump(r);
}

TEST(Validate, LimitsCoherence) {
    const auto r = load_config_string(R"(
mode: client
limits: { idle_timeout: 2h, session_lifetime: 1h, renegotiation_grace: 40m, session_jitter: 60%,
          resume_buffer: 1KiB, max_channels: 0 }
ports: { plain: { listen: "127.0.0.1:7001", upstream: "h:1" } }
)");
    EXPECT_TRUE(has_error(r, "limits.idle_timeout", "session_lifetime")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.renegotiation_grace")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.session_jitter")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.resume_buffer")) << dump(r);
    EXPECT_TRUE(has_error(r, "limits.max_channels")) << dump(r);
}

TEST(Validate, InstanceNameAndLogOutput) {
    const auto r = load_config_string(R"(
mode: client
instance: "nom avec espaces"
logging: { output: syslog }
ports: { plain: { listen: "127.0.0.1:7001", upstream: "h:1" } }
)");
    EXPECT_TRUE(has_error(r, "instance")) << dump(r);
    EXPECT_TRUE(has_error(r, "logging.output", "pas encore")) << dump(r);
}

TEST(Validate, ProgrammaticConfigUsesSameRules) {
    // L'éditeur construit la configuration sans YAML : même validation.
    Config c;
    c.mode = Mode::server;
    c.ports[PortKind::plain].listen = Endpoint{"0.0.0.0", 9001};
    std::vector<Issue> errors, warnings;
    validate(c, errors, warnings);
    ASSERT_EQ(errors.size(), 2u);
    EXPECT_EQ(errors[0].path, "destination");
    EXPECT_EQ(errors[1].path, "whitelist");
}
