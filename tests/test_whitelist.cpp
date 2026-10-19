// Whitelist (SPEC §6): file format, IP ranges, subjects, authorization.

#include "tlsrelay/whitelist.hpp"

#include <gtest/gtest.h>

#include <algorithm>

using namespace tlsrelay;
using namespace tlsrelay::whitelist;

namespace {

asio::ip::address ip(const char* text) { return asio::ip::make_address(text); }

tls::X509NamePtr dn(const char* text) {
    std::string error;
    auto name = tls::parse_dn(text, error);
    EXPECT_TRUE(name) << text << ": " << error;
    return name;
}

bool has_error(const whitelist::LoadResult& r, const std::string& path, const std::string& fragment = "") {
    return std::any_of(r.errors.begin(), r.errors.end(), [&](const Issue& i) {
        return i.path == path && i.message.find(fragment) != std::string::npos;
    });
}

std::string dump(const whitelist::LoadResult& r) {
    std::string s;
    for (const auto& e : r.errors) s += e.path + ": " + e.message + "\n";
    return s;
}

const char* kList = R"(
peers:
  - name: branch-lyon
    ip: 192.0.2.10
    ports: [mtls]
    subject: "CN=relay-lyon.example,O=MyCompany"
  - name: lab
    ip: 198.51.100.0/28
  - name: hq
    ip: "2001:db8::/32"
    subject: "CN=hq.example,O=MyCompany"
)";

}  // namespace

TEST(Whitelist, LoadsEntriesWithDefaults) {
    const auto r = Whitelist::load_string(kList);
    ASSERT_TRUE(r.whitelist) << dump(r);
    const auto& peers = r.whitelist->peers();
    ASSERT_EQ(peers.size(), 3u);
    EXPECT_EQ(peers[0].ports, (std::set<PortKind>{PortKind::mtls}));
    // Without a port list or subject: plain and tls only.
    EXPECT_EQ(peers[1].ports, (std::set<PortKind>{PortKind::plain, PortKind::tls}));
    EXPECT_EQ(peers[1].range.to_string(), "198.51.100.0/28");
    // Without a port list but with a subject: all ports.
    EXPECT_EQ(peers[2].ports, (std::set<PortKind>{PortKind::plain, PortKind::tls, PortKind::mtls}));
    EXPECT_TRUE(r.warnings.empty());
}

TEST(Whitelist, ReportsFormatErrors) {
    const auto r = Whitelist::load_string(R"(
extra: 1
peers:
  - name: a
    ip: 300.0.0.1
    colour: blue
  - name: a
    ip: 192.0.2.5/28
  - name: c
    ip: 10.0.0.0/33
  - ip: 10.0.0.1
  - name: e
    ip: 10.0.0.2
    ports: [mtls]
  - name: f
    ip: 10.0.0.3
    ports: [ssh]
  - name: g
    ip: 10.0.0.4
    subject: "CN=x+O=y"
  - name: h
    ip: 10.0.0.5
    subject: "XX=unknown"
  - name: i
    ip: 10.0.0.6
    ports: []
)");
    EXPECT_FALSE(r.whitelist);
    EXPECT_TRUE(has_error(r, "extra", "unknown key")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[0].ip", "invalid IP address")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[0].colour", "unknown key")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[1].name", "already used")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[1].ip", "host bits")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[2].ip", "prefix")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[3].name", "required")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[4].subject", "required when the mtls port")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[5].ports", "unknown port")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[6].subject", "multi-valued")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[7].subject", "unknown attribute")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[8].ports", "non-empty list")) << dump(r);
}

TEST(Whitelist, RejectsSameSubjectTwice) {
    const auto r = Whitelist::load_string(R"(
peers:
  - { name: a, ip: 10.0.0.1, subject: "CN=x,O=y" }
  - { name: b, ip: 10.0.0.2, subject: "cn=X, o=Y" }
)");
    EXPECT_TRUE(has_error(r, "peers", "used by \"a\" and \"b\"")) << dump(r);
}

TEST(Whitelist, RequiresPeersSection) {
    EXPECT_TRUE(has_error(Whitelist::load_string("other: 1"), "peers", "required"));
    EXPECT_TRUE(has_error(Whitelist::load_string("peers: 5"), "peers", "list"));
    EXPECT_FALSE(Whitelist::load_string("peers: [unclosed").whitelist);
}

TEST(Whitelist, EmptyListIsValidWithWarning) {
    const auto r = Whitelist::load_string("peers: []");
    ASSERT_TRUE(r.whitelist);
    ASSERT_EQ(r.warnings.size(), 1u);
    EXPECT_FALSE(r.whitelist->admits(ip("127.0.0.1"), PortKind::plain));
}

TEST(IpRange, MatchesAddresses) {
    std::string error;
    auto single = parse_ip_range("192.0.2.10", error);
    ASSERT_TRUE(single);
    EXPECT_TRUE(single->contains(ip("192.0.2.10")));
    EXPECT_FALSE(single->contains(ip("192.0.2.11")));

    auto net = parse_ip_range("198.51.100.0/28", error);
    ASSERT_TRUE(net);
    EXPECT_TRUE(net->contains(ip("198.51.100.15")));
    EXPECT_FALSE(net->contains(ip("198.51.100.16")));
    // IPv4 address seen through an IPv6 socket.
    EXPECT_TRUE(net->contains(ip("::ffff:198.51.100.3")));
    EXPECT_FALSE(net->contains(ip("2001:db8::1")));

    auto v6 = parse_ip_range("2001:db8::/32", error);
    ASSERT_TRUE(v6);
    EXPECT_TRUE(v6->contains(ip("2001:db8:ffff::1")));
    EXPECT_FALSE(v6->contains(ip("2001:db9::1")));

    auto all = parse_ip_range("0.0.0.0/0", error);
    ASSERT_TRUE(all);
    EXPECT_TRUE(all->contains(ip("203.0.113.7")));
}

TEST(Whitelist, AuthorizesByIpAndPort) {
    const auto r = Whitelist::load_string(kList);
    ASSERT_TRUE(r.whitelist) << dump(r);
    const auto& wl = *r.whitelist;

    EXPECT_TRUE(wl.admits(ip("198.51.100.3"), PortKind::plain));
    EXPECT_TRUE(wl.admits(ip("198.51.100.3"), PortKind::tls));
    EXPECT_FALSE(wl.admits(ip("198.51.100.3"), PortKind::mtls));
    EXPECT_FALSE(wl.admits(ip("192.0.2.10"), PortKind::plain));  // branch-lyon: mtls only
    EXPECT_TRUE(wl.admits(ip("192.0.2.10"), PortKind::mtls));
    EXPECT_FALSE(wl.admits(ip("203.0.113.1"), PortKind::tls));

    const auto* lab = wl.authorize(ip("198.51.100.3"), PortKind::tls, nullptr);
    ASSERT_TRUE(lab);
    EXPECT_EQ(lab->name, "lab");
}

TEST(Whitelist, MtlsRequiresIpAndSubjectInTheSameEntry) {
    const auto r = Whitelist::load_string(kList);
    ASSERT_TRUE(r.whitelist) << dump(r);
    const auto& wl = *r.whitelist;
    const auto lyon = dn("CN=relay-lyon.example,O=MyCompany");
    const auto hq = dn("CN=hq.example,O=MyCompany");

    const auto* peer = wl.authorize(ip("192.0.2.10"), PortKind::mtls, lyon.get());
    ASSERT_TRUE(peer);
    EXPECT_EQ(peer->name, "branch-lyon");
    // Canonical comparison: case and spaces have no effect.
    EXPECT_TRUE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, dn("cn=Relay-Lyon.example,  o=mycompany").get()));
    // Right subject but IP of another entry, and vice versa.
    EXPECT_FALSE(wl.authorize(ip("2001:db8::1"), PortKind::mtls, lyon.get()));
    EXPECT_FALSE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, hq.get()));
    // Missing subject or different component order.
    EXPECT_FALSE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, nullptr));
    EXPECT_FALSE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, dn("O=MyCompany,CN=relay-lyon.example").get()));
}

TEST(Dn, ParsesEscapesAndMatchesCertificateForm) {
    const auto a = dn(R"(CN=relay\, lyon,O=Soci\C3\A9t\C3\A9 SA)");
    const auto b = dn("CN=relay\\, lyon,O=Société SA");
    ASSERT_TRUE(a && b);
    EXPECT_EQ(X509_NAME_cmp(a.get(), b.get()), 0);
    EXPECT_EQ(tls::name_to_string(b.get()), "CN=relay\\, lyon,O=Société SA");

    std::string error;
    EXPECT_FALSE(tls::parse_dn("CN", error));
    EXPECT_FALSE(tls::parse_dn("CN=a,", error));
    EXPECT_FALSE(tls::parse_dn("CN=#0403", error));
}

TEST(Whitelist, DiffReportsChanges) {
    const auto before = Whitelist::load_string(R"(
peers:
  - { name: a, ip: 10.0.0.1 }
  - { name: b, ip: 10.0.0.2 }
  - { name: c, ip: 10.0.0.3 }
)");
    const auto after = Whitelist::load_string(R"(
peers:
  - { name: a, ip: 10.0.0.1 }
  - { name: b, ip: 10.0.0.20 }
  - { name: d, ip: 10.0.0.4 }
)");
    ASSERT_TRUE(before.whitelist && after.whitelist);
    const auto d = diff(*before.whitelist, *after.whitelist);
    EXPECT_EQ(d.added, std::vector<std::string>{"d"});
    EXPECT_EQ(d.removed, std::vector<std::string>{"c"});
    EXPECT_EQ(d.changed, std::vector<std::string>{"b"});
}

// File structure (CT-13): each error points to its location.
TEST(Whitelist, StructureErrors) {
    auto r = whitelist::Whitelist::load_string("- a\n- b\n");
    EXPECT_TRUE(has_error(r, "(root)", "peers")) << dump(r);

    r = whitelist::Whitelist::load_string("peers: []\nothers: 1\n");
    EXPECT_TRUE(has_error(r, "others", "unknown key")) << dump(r);

    r = whitelist::Whitelist::load_string("peers: { name: a }\n");
    EXPECT_TRUE(has_error(r, "peers", "list")) << dump(r);

    r = whitelist::Whitelist::load_string("peers:\n  - host\n  - { name: [a, b], ip: 10.0.0.1 }\n");
    EXPECT_TRUE(has_error(r, "peers[0]", "entry")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[1].name", "scalar value")) << dump(r);
    EXPECT_FALSE(r.whitelist);

    r = whitelist::Whitelist::load_string("peers: [\n");
    EXPECT_FALSE(r.errors.empty());
    EXPECT_NE(r.errors.front().path.find("line"), std::string::npos) << dump(r);
}

TEST(Whitelist, MissingFileIsReported) {
    const auto r = whitelist::Whitelist::load_file("/nonexistent/whitelist.yaml");
    ASSERT_EQ(r.errors.size(), 1u);
    EXPECT_NE(r.errors.front().message.find("missing or unreadable"), std::string::npos);
}
