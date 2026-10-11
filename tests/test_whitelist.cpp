// Liste blanche (SPEC §6) : format du fichier, plages IP, sujets, autorisation.

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
    EXPECT_TRUE(name) << text << " : " << error;
    return name;
}

bool has_error(const whitelist::LoadResult& r, const std::string& path, const std::string& fragment = "") {
    return std::any_of(r.errors.begin(), r.errors.end(), [&](const Issue& i) {
        return i.path == path && i.message.find(fragment) != std::string::npos;
    });
}

std::string dump(const whitelist::LoadResult& r) {
    std::string s;
    for (const auto& e : r.errors) s += e.path + " : " + e.message + "\n";
    return s;
}

const char* kList = R"(
peers:
  - name: agence-lyon
    ip: 192.0.2.10
    ports: [mtls]
    subject: "CN=relay-lyon.example,O=MonEntreprise"
  - name: labo
    ip: 198.51.100.0/28
  - name: siege
    ip: "2001:db8::/32"
    subject: "CN=siege.example,O=MonEntreprise"
)";

}  // namespace

TEST(Whitelist, LoadsEntriesWithDefaults) {
    const auto r = Whitelist::load_string(kList);
    ASSERT_TRUE(r.whitelist) << dump(r);
    const auto& peers = r.whitelist->peers();
    ASSERT_EQ(peers.size(), 3u);
    EXPECT_EQ(peers[0].ports, (std::set<PortKind>{PortKind::mtls}));
    // Sans liste de ports ni sujet : plain et tls seulement.
    EXPECT_EQ(peers[1].ports, (std::set<PortKind>{PortKind::plain, PortKind::tls}));
    EXPECT_EQ(peers[1].range.to_string(), "198.51.100.0/28");
    // Sans liste de ports mais avec sujet : tous les ports.
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
    subject: "XX=inconnu"
  - name: i
    ip: 10.0.0.6
    ports: []
)");
    EXPECT_FALSE(r.whitelist);
    EXPECT_TRUE(has_error(r, "extra", "clé inconnue")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[0].ip", "adresse IP invalide")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[0].colour", "clé inconnue")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[1].name", "déjà utilisé")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[1].ip", "bits d'hôte")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[2].ip", "préfixe")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[3].name", "obligatoire")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[4].subject", "obligatoire quand le port mtls")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[5].ports", "port inconnu")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[6].subject", "plusieurs valeurs")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[7].subject", "attribut inconnu")) << dump(r);
    EXPECT_TRUE(has_error(r, "peers[8].ports", "liste non vide")) << dump(r);
}

TEST(Whitelist, RejectsSameSubjectTwice) {
    const auto r = Whitelist::load_string(R"(
peers:
  - { name: a, ip: 10.0.0.1, subject: "CN=x,O=y" }
  - { name: b, ip: 10.0.0.2, subject: "cn=X, o=Y" }
)");
    EXPECT_TRUE(has_error(r, "peers", "utilisé par « a » et « b »")) << dump(r);
}

TEST(Whitelist, RequiresPeersSection) {
    EXPECT_TRUE(has_error(Whitelist::load_string("autre: 1"), "peers", "obligatoire"));
    EXPECT_TRUE(has_error(Whitelist::load_string("peers: 5"), "peers", "liste"));
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
    // Adresse IPv4 vue à travers une socket IPv6.
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
    EXPECT_FALSE(wl.admits(ip("192.0.2.10"), PortKind::plain));  // agence-lyon : mtls uniquement
    EXPECT_TRUE(wl.admits(ip("192.0.2.10"), PortKind::mtls));
    EXPECT_FALSE(wl.admits(ip("203.0.113.1"), PortKind::tls));

    const auto* labo = wl.authorize(ip("198.51.100.3"), PortKind::tls, nullptr);
    ASSERT_TRUE(labo);
    EXPECT_EQ(labo->name, "labo");
}

TEST(Whitelist, MtlsRequiresIpAndSubjectInTheSameEntry) {
    const auto r = Whitelist::load_string(kList);
    ASSERT_TRUE(r.whitelist) << dump(r);
    const auto& wl = *r.whitelist;
    const auto lyon = dn("CN=relay-lyon.example,O=MonEntreprise");
    const auto siege = dn("CN=siege.example,O=MonEntreprise");

    const auto* peer = wl.authorize(ip("192.0.2.10"), PortKind::mtls, lyon.get());
    ASSERT_TRUE(peer);
    EXPECT_EQ(peer->name, "agence-lyon");
    // Comparaison canonique : casse et espaces sans effet.
    EXPECT_TRUE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, dn("cn=Relay-Lyon.example,  o=monentreprise").get()));
    // Bon sujet mais IP d'une autre entrée, et inversement.
    EXPECT_FALSE(wl.authorize(ip("2001:db8::1"), PortKind::mtls, lyon.get()));
    EXPECT_FALSE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, siege.get()));
    // Sujet absent ou ordre des composants différent.
    EXPECT_FALSE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, nullptr));
    EXPECT_FALSE(wl.authorize(ip("192.0.2.10"), PortKind::mtls, dn("O=MonEntreprise,CN=relay-lyon.example").get()));
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
