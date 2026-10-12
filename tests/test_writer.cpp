// Écriture normalisée de la configuration et de la liste blanche, et
// différences de texte (socle de l'éditeur tlsrelay-admin).
#include "tlsrelay/config.hpp"
#include "tlsrelay/text_diff.hpp"
#include "tlsrelay/units.hpp"
#include "tlsrelay/whitelist.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

using namespace tlsrelay;
using namespace std::chrono_literals;

namespace {

std::string read(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

std::string dump(const std::vector<Issue>& issues) {
    std::string s;
    for (const auto& i : issues) s += i.path + " : " + i.message + "\n";
    return s;
}

Config reload(const Config& cfg) {
    const auto text = to_yaml(cfg);
    auto result = load_config_string(text);
    EXPECT_TRUE(result.config) << dump(result.errors) << text;
    return result.config ? *result.config : Config{};
}

}  // namespace

TEST(Units, FormatSizeAndPercentRoundTrip) {
    for (std::uint64_t v : {0ULL, 1ULL, 1000ULL, 1024ULL, 65536ULL, 4ULL << 20, 3ULL << 30, (1ULL << 20) + 1}) {
        EXPECT_EQ(parse_size(format_size(v)), v) << format_size(v);
    }
    EXPECT_EQ(format_size(4ULL << 20), "4MiB");
    for (double f : {0.0, 0.1, 0.05, 0.125, 0.333, 0.5, 1.0, 0.07}) {
        EXPECT_EQ(parse_percent(format_percent(f)), f) << format_percent(f);
    }
    EXPECT_EQ(format_percent(0.1), "10%");
}

TEST(ConfigWriter, ExamplesRoundTrip) {
    for (const char* name : {"client.yaml", "server.yaml"}) {
        auto original = load_config_string(read(std::string(TLSRELAY_EXAMPLES_DIR) + "/" + name));
        ASSERT_TRUE(original.config) << name << dump(original.errors);
        EXPECT_EQ(reload(*original.config), *original.config) << name;
    }
}

TEST(ConfigWriter, EveryFieldRoundTrips) {
    Config c;
    c.mode = Mode::client;
    c.instance = "agence-2";
    c.logging = {LogLevel::debug, LogLevel::trace, LogLevel::error, LogFormat::json, "/var/log/tlsrelay/a b.log"};
    c.credentials = Credentials{"C:\\ProgramData\\tlsrelay\\pki", false, std::chrono::days(10)};
    c.limits.idle_timeout = 90s;
    c.limits.session_lifetime = 2h;
    c.limits.session_jitter = 0.07;
    c.limits.renegotiation_grace = 1500ms;
    c.limits.resume_buffer = 1ULL << 20;
    c.limits.handshake_timeout = 3s;
    c.limits.keepalive_interval = 0ms;
    c.limits.max_channels = 42;
    c.limits.shutdown_timeout = 0ms;
    c.ports[PortKind::plain] = {{"127.0.0.1", 7001}, Endpoint{"relay.example", 9001}, std::nullopt};
    c.ports[PortKind::tls] = {{"::1", 7002}, Endpoint{"2001:db8::1", 9002}, std::string("relay.example")};
    c.ports[PortKind::mtls] = {{"127.0.0.1", 7003}, Endpoint{"relay.example", 9003}, std::string("192.0.2.1")};
    c.source_address = "127.0.0.2";
    c.admin = {false, std::string("/run/a: #b")};
    EXPECT_EQ(reload(c), c) << to_yaml(c);

    Config s;
    s.mode = Mode::server;
    s.credentials = Credentials{"/etc/tlsrelay/pki"};
    s.ports[PortKind::mtls] = {{"0.0.0.0", 9003}, std::nullopt, std::nullopt};
    s.destination = Destination{{"db.local", 5432}, 2s, 5, 250ms};
    s.whitelist = WhitelistRef{"whitelist.yaml", RevokeMode::next_renegotiation};
    EXPECT_EQ(reload(s), s) << to_yaml(s);
}

TEST(ConfigWriter, DefaultsAreOmittedAndHeaderIsCommented) {
    Config s;
    s.mode = Mode::server;
    s.ports[PortKind::plain] = {{"0.0.0.0", 9001}, std::nullopt, std::nullopt};
    s.destination = Destination{{"10.0.0.5", 8080}};
    s.whitelist = WhitelistRef{"wl.yaml"};
    const auto text = to_yaml(s, "Écrit par tlsrelay-admin\n\nligne 3");
    EXPECT_EQ(text.rfind("# Écrit par tlsrelay-admin\n#\n# ligne 3\nmode: server\n", 0), 0u) << text;
    const auto body = text.substr(text.find("mode:"));
    for (const char* absent : {"limits", "logging", "admin", "dial_timeout", "revoke_mode"}) {
        EXPECT_EQ(body.find(absent), std::string::npos) << absent << "\n" << text;
    }
    EXPECT_EQ(reload(s), s);
}

TEST(WhitelistWriter, RoundTripKeepsDefaultPorts) {
    const std::vector<whitelist::PeerSpec> specs = {
        {"site-a", "192.0.2.10", std::nullopt, ""},
        {"site-b", "198.51.100.0/24", std::set<PortKind>{PortKind::mtls}, "CN=site-b,O=Exemple"},
        {"site-c", "2001:db8::/32", std::set<PortKind>{PortKind::plain, PortKind::tls}, "CN=a: #b,O=x"},
        {"site-d", "203.0.113.7", std::nullopt, "CN=site-d"},
    };
    const auto text = whitelist::to_yaml(specs, "Liste blanche");
    auto result = whitelist::Whitelist::load_string(text);
    ASSERT_TRUE(result.whitelist) << dump(result.errors) << text;
    std::vector<whitelist::PeerSpec> back;
    for (const auto& p : result.whitelist->peers()) back.push_back(whitelist::to_spec(p));
    EXPECT_EQ(back, specs) << text;
    EXPECT_TRUE(result.whitelist->peers()[3].ports.count(PortKind::mtls));  // défaut avec sujet

    const auto empty = whitelist::to_yaml({});
    auto none = whitelist::Whitelist::load_string(empty);
    ASSERT_TRUE(none.whitelist) << empty;
    EXPECT_TRUE(none.whitelist->peers().empty());
}

TEST(WhitelistWriter, ExampleRoundTrip) {
    auto original = whitelist::Whitelist::load_string(read(std::string(TLSRELAY_EXAMPLES_DIR) + "/whitelist.yaml"));
    ASSERT_TRUE(original.whitelist) << dump(original.errors);
    std::vector<whitelist::PeerSpec> specs;
    for (const auto& p : original.whitelist->peers()) specs.push_back(whitelist::to_spec(p));
    auto again = whitelist::Whitelist::load_string(whitelist::to_yaml(specs));
    ASSERT_TRUE(again.whitelist);
    EXPECT_TRUE(whitelist::diff(*original.whitelist, *again.whitelist).empty());
}

TEST(TextDiff, LinesAddedRemovedAndChanged) {
    const auto d = diff_lines("a\nb\nc\nd\n", "a\nB\nc\nd\ne\n");
    std::string marks;
    for (const auto& l : d) marks += (l.kind == DiffLine::Kind::same ? '=' : l.kind == DiffLine::Kind::added ? '+' : '-');
    EXPECT_EQ(marks, "=-+==+");
    EXPECT_EQ(d[1].text, "b");
    EXPECT_EQ(d[2].text, "B");
    EXPECT_FALSE(same_lines(d));
    EXPECT_TRUE(same_lines(diff_lines("x\r\ny\r\n", "x\ny")));
    EXPECT_TRUE(diff_lines("", "").empty());
    EXPECT_EQ(diff_lines("", "a\n").size(), 1u);
}

TEST(TextDiff, FormatKeepsContext) {
    std::string before, after;
    for (int i = 0; i < 20; ++i) {
        before += "l" + std::to_string(i) + "\n";
        after += (i == 10 ? std::string("X") : "l" + std::to_string(i)) + "\n";
    }
    const auto text = format_diff(diff_lines(before, after), 2);
    EXPECT_EQ(text, " l8\n l9\n-l10\n+X\n l11\n l12\n");
    EXPECT_EQ(format_diff(diff_lines("a\n", "a\n")), "");
}
