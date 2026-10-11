#include "tlsrelay/whitelist.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>

namespace tlsrelay::whitelist {
namespace {

std::array<unsigned char, 16> bytes_of(const asio::ip::address& a) {
    std::array<unsigned char, 16> out{};
    if (a.is_v4()) {
        const auto b = a.to_v4().to_bytes();
        std::copy(b.begin(), b.end(), out.begin());
    } else {
        out = a.to_v6().to_bytes();
    }
    return out;
}

bool prefix_matches(const asio::ip::address& a, const asio::ip::address& b, unsigned prefix) {
    const auto x = bytes_of(a);
    const auto y = bytes_of(b);
    const unsigned full = prefix / 8;
    for (unsigned i = 0; i < full; ++i) {
        if (x[i] != y[i]) return false;
    }
    const unsigned rest = prefix % 8;
    if (rest == 0) return true;
    const auto mask = static_cast<unsigned char>(0xFF << (8 - rest));
    return (x[full] & mask) == (y[full] & mask);
}

std::optional<PortKind> parse_port_kind(const std::string& text) {
    if (text == "plain") return PortKind::plain;
    if (text == "tls") return PortKind::tls;
    if (text == "mtls") return PortKind::mtls;
    return std::nullopt;
}

}  // namespace

bool IpRange::contains(const asio::ip::address& address) const {
    const auto a = normalize(address);
    if (a.is_v4() != network.is_v4()) return false;
    return prefix_matches(a, network, prefix);
}

std::string IpRange::to_string() const {
    const unsigned full = network.is_v4() ? 32 : 128;
    return network.to_string() + (prefix == full ? "" : "/" + std::to_string(prefix));
}

std::optional<IpRange> parse_ip_range(std::string_view text, std::string& error) {
    const auto slash = text.find('/');
    std::error_code ec;
    const auto address = asio::ip::make_address(std::string(text.substr(0, slash)), ec);
    if (ec) {
        error = "adresse IP invalide « " + std::string(text) + " »";
        return std::nullopt;
    }
    IpRange range;
    range.network = normalize(address);
    const unsigned full = range.network.is_v4() ? 32u : 128u;
    range.prefix = full;
    if (slash != std::string_view::npos) {
        const auto digits = text.substr(slash + 1);
        unsigned prefix = 0;
        auto [end, pec] = std::from_chars(digits.data(), digits.data() + digits.size(), prefix);
        if (digits.empty() || pec != std::errc{} || end != digits.data() + digits.size() || prefix > full) {
            error = "longueur de préfixe invalide dans « " + std::string(text) + " »";
            return std::nullopt;
        }
        range.prefix = prefix;
    }
    // Les bits hors du préfixe doivent être nuls : 192.0.2.5/28 est probablement une erreur de saisie.
    const auto bytes = bytes_of(range.network);
    for (unsigned bit = range.prefix; bit < full; ++bit) {
        if (bytes[bit / 8] & (0x80 >> (bit % 8))) {
            error = "bits d'hôte non nuls dans « " + std::string(text) + " » (adresse du réseau attendue)";
            return std::nullopt;
        }
    }
    return range;
}

asio::ip::address normalize(const asio::ip::address& address) {
    if (address.is_v6() && address.to_v6().is_v4_mapped()) {
        return asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
    }
    return address;
}

bool Peer::same_as(const Peer& other) const {
    return name == other.name && range.to_string() == other.range.to_string() && ports == other.ports &&
           subject_text == other.subject_text;
}

LoadResult Whitelist::load_string(std::string_view yaml) {
    LoadResult result;
    auto err = [&](std::string path, std::string message) {
        result.errors.push_back({std::move(path), std::move(message)});
    };

    YAML::Node root;
    try {
        root = YAML::Load(std::string(yaml));
    } catch (const YAML::Exception& e) {
        std::ostringstream where;
        where << "ligne " << (e.mark.line + 1) << ", colonne " << (e.mark.column + 1);
        err(where.str(), "syntaxe YAML invalide : " + e.msg);
        return result;
    }
    if (!root.IsMap()) {
        err("(racine)", "une section « peers » est attendue");
        return result;
    }
    for (const auto& item : root) {
        if (item.first.as<std::string>("") != "peers") err(item.first.as<std::string>(""), "clé inconnue");
    }
    const YAML::Node peers = root["peers"];
    if (!peers.IsDefined() || peers.IsNull()) {
        err("peers", "valeur obligatoire manquante (liste éventuellement vide : peers: [])");
        return result;
    }
    if (!peers.IsSequence()) {
        err("peers", "une liste est attendue");
        return result;
    }

    auto wl = std::make_shared<Whitelist>();
    std::map<std::string, std::size_t> names;
    std::size_t index = 0;
    for (const auto& node : peers) {
        const std::string path = "peers[" + std::to_string(index++) + "]";
        if (!node.IsMap()) {
            err(path, "une entrée (name, ip, ports, subject) est attendue");
            continue;
        }
        for (const auto& item : node) {
            const auto key = item.first.as<std::string>("");
            if (key != "name" && key != "ip" && key != "ports" && key != "subject") err(path + "." + key, "clé inconnue");
        }
        auto scalar = [&](const char* key) -> std::optional<std::string> {
            const YAML::Node v = node[key];
            if (!v.IsDefined()) return std::nullopt;
            if (!v.IsScalar()) {
                err(path + "." + key, "une valeur simple est attendue");
                return std::nullopt;
            }
            return v.Scalar();
        };

        Peer peer;
        bool ok = true;
        if (auto name = scalar("name"); name && !name->empty()) {
            peer.name = *name;
            if (auto [it, inserted] = names.emplace(*name, index - 1); !inserted) {
                err(path + ".name", "nom déjà utilisé par peers[" + std::to_string(it->second) + "]");
                ok = false;
            }
        } else {
            err(path + ".name", "valeur obligatoire manquante");
            ok = false;
        }

        if (auto ip = scalar("ip")) {
            std::string error;
            if (auto range = parse_ip_range(*ip, error)) peer.range = *range;
            else {
                err(path + ".ip", error);
                ok = false;
            }
        } else {
            err(path + ".ip", "valeur obligatoire manquante");
            ok = false;
        }

        if (auto subject = scalar("subject")) {
            std::string error;
            auto name = tls::parse_dn(*subject, error);
            if (!name) {
                err(path + ".subject", "sujet invalide : " + error);
                ok = false;
            } else {
                peer.subject_text = *subject;
                peer.subject = std::shared_ptr<const X509_NAME>(name.release(), [](const X509_NAME* n) {
                    X509_NAME_free(const_cast<X509_NAME*>(n));
                });
            }
        }

        const YAML::Node ports = node["ports"];
        if (ports.IsDefined()) {
            if (!ports.IsSequence() || ports.size() == 0) {
                err(path + ".ports", "liste non vide attendue, parmi plain, tls, mtls");
                ok = false;
            } else {
                for (const auto& p : ports) {
                    const auto kind = p.IsScalar() ? parse_port_kind(p.Scalar()) : std::nullopt;
                    if (!kind) {
                        err(path + ".ports", "port inconnu (plain, tls ou mtls attendu)");
                        ok = false;
                    } else {
                        peer.ports.insert(*kind);
                    }
                }
                if (peer.ports.count(PortKind::mtls) && !peer.subject) {
                    err(path + ".subject", "obligatoire quand le port mtls est autorisé");
                    ok = false;
                }
            }
        } else {
            // Sans liste de ports : tous les ports, sauf mtls si aucun sujet n'est donné.
            peer.ports = {PortKind::plain, PortKind::tls};
            if (peer.subject) peer.ports.insert(PortKind::mtls);
        }
        if (ok) wl->peers_.push_back(std::move(peer));
    }

    // Un même sujet ne peut pas désigner deux pairs.
    for (std::size_t i = 0; i < wl->peers_.size(); ++i) {
        for (std::size_t j = i + 1; j < wl->peers_.size(); ++j) {
            const auto& a = wl->peers_[i];
            const auto& b = wl->peers_[j];
            if (a.subject && b.subject && X509_NAME_cmp(a.subject.get(), b.subject.get()) == 0) {
                err("peers", "le sujet « " + b.subject_text + " » est utilisé par « " + a.name + " » et « " + b.name +
                                 " »");
            }
        }
    }
    if (result.errors.empty() && wl->peers_.empty()) {
        result.warnings.push_back({"peers", "liste vide : aucune connexion ne sera acceptée"});
    }
    if (result.errors.empty()) result.whitelist = std::move(wl);
    return result;
}

LoadResult Whitelist::load_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        LoadResult result;
        result.errors.push_back({path.string(), "fichier absent ou illisible"});
        return result;
    }
    std::ostringstream text;
    text << in.rdbuf();
    auto result = load_string(text.str());
    for (auto& e : result.errors) e.path = path.string() + " : " + e.path;
    for (auto& w : result.warnings) w.path = path.string() + " : " + w.path;
    return result;
}

bool Whitelist::admits(const asio::ip::address& address, PortKind port) const {
    return std::any_of(peers_.begin(), peers_.end(),
                       [&](const Peer& p) { return p.ports.count(port) && p.range.contains(address); });
}

const Peer* Whitelist::authorize(const asio::ip::address& address, PortKind port, const X509_NAME* subject) const {
    for (const auto& p : peers_) {
        if (!p.ports.count(port) || !p.range.contains(address)) continue;
        if (port != PortKind::mtls) return &p;
        if (subject && p.subject && X509_NAME_cmp(p.subject.get(), subject) == 0) return &p;
    }
    return nullptr;
}

Diff diff(const Whitelist& before, const Whitelist& after) {
    Diff d;
    auto find = [](const Whitelist& wl, const std::string& name) -> const Peer* {
        for (const auto& p : wl.peers()) {
            if (p.name == name) return &p;
        }
        return nullptr;
    };
    for (const auto& p : after.peers()) {
        const Peer* old = find(before, p.name);
        if (!old) d.added.push_back(p.name);
        else if (!old->same_as(p)) d.changed.push_back(p.name);
    }
    for (const auto& p : before.peers()) {
        if (!find(after, p.name)) d.removed.push_back(p.name);
    }
    return d;
}

}  // namespace tlsrelay::whitelist
