#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"

#include <asio/ip/address.hpp>

#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

// Liste blanche des pairs autorisés à se connecter au tlsrelay serveur (SPEC §6).
namespace tlsrelay::whitelist {

// Adresse IP ou plage CIDR (IPv4 ou IPv6).
struct IpRange {
    asio::ip::address network;
    unsigned prefix = 0;

    bool contains(const asio::ip::address& address) const;
    std::string to_string() const;
};

// "192.0.2.10", "192.0.2.0/28", "2001:db8::/32". Retourne std::nullopt et remplit error sinon.
std::optional<IpRange> parse_ip_range(std::string_view text, std::string& error);

// Une IPv4 vue à travers une socket IPv6 (::ffff:a.b.c.d) redevient une IPv4.
asio::ip::address normalize(const asio::ip::address& address);

struct Peer {
    std::string name;
    IpRange range;
    std::set<PortKind> ports;
    std::string subject_text;                // tel qu'écrit dans le fichier, vide si absent
    std::shared_ptr<const X509_NAME> subject;  // forme comparable, nullptr si absent

    // Même définition (pour le calcul des différences au rechargement).
    bool same_as(const Peer& other) const;
};

class Whitelist;

struct LoadResult {
    std::shared_ptr<const Whitelist> whitelist;  // présent seulement si errors est vide
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

class Whitelist {
public:
    static LoadResult load_string(std::string_view yaml);
    static LoadResult load_file(const std::filesystem::path& path);

    // Contrôle avant handshake : une entrée contient l'adresse et autorise ce port.
    bool admits(const asio::ip::address& address, PortKind port) const;

    // Contrôle complet. Port mtls : il faut une entrée qui contient l'adresse,
    // autorise mtls et dont le sujet est exactement celui du certificat (les
    // deux critères dans la même entrée). Autres ports : l'adresse suffit.
    // Retourne l'entrée autorisée, ou nullptr.
    const Peer* authorize(const asio::ip::address& address, PortKind port, const X509_NAME* subject) const;

    const std::vector<Peer>& peers() const { return peers_; }

private:
    std::vector<Peer> peers_;
};

struct Diff {
    std::vector<std::string> added;
    std::vector<std::string> removed;
    std::vector<std::string> changed;
    bool empty() const { return added.empty() && removed.empty() && changed.empty(); }
};

Diff diff(const Whitelist& before, const Whitelist& after);

}  // namespace tlsrelay::whitelist
