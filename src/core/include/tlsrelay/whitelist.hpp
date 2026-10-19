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

// Whitelist of the peers allowed to connect to the server tlsrelay (SPEC §6).
namespace tlsrelay::whitelist {

// IP address or CIDR range (IPv4 or IPv6).
struct IpRange {
    asio::ip::address network;
    unsigned prefix = 0;

    bool contains(const asio::ip::address& address) const;
    std::string to_string() const;
};

// "192.0.2.10", "192.0.2.0/28", "2001:db8::/32". Otherwise returns std::nullopt and fills error.
std::optional<IpRange> parse_ip_range(std::string_view text, std::string& error);

// An IPv4 address seen through an IPv6 socket (::ffff:a.b.c.d) becomes IPv4 again.
asio::ip::address normalize(const asio::ip::address& address);

struct Peer {
    std::string name;
    IpRange range;
    std::set<PortKind> ports;
    bool ports_explicit = false;             // ports given in the file (otherwise the default)
    std::string subject_text;                // as written in the file, empty if absent
    std::shared_ptr<const X509_NAME> subject;  // comparable form, nullptr if absent

    // Same definition (for computing differences on reload).
    bool same_as(const Peer& other) const;
};

class Whitelist;

struct LoadResult {
    std::shared_ptr<const Whitelist> whitelist;  // present only if errors is empty
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

class Whitelist {
public:
    static LoadResult load_string(std::string_view yaml);
    static LoadResult load_file(const std::filesystem::path& path);

    // Check before the handshake: an entry contains the address and allows this port.
    bool admits(const asio::ip::address& address, PortKind port) const;

    // Full check. mtls port: an entry must contain the address, allow mtls
    // and have exactly the certificate's subject (both criteria in the same
    // entry). Other ports: the address is enough.
    // Returns the authorized entry, or nullptr.
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

// Entry as written in the file (tlsrelay-admin editor).
struct PeerSpec {
    std::string name;
    std::string ip;
    std::optional<std::set<PortKind>> ports;  // absent: default value (SPEC §6)
    std::string subject;                      // empty: absent

    bool operator==(const PeerSpec&) const = default;
};

PeerSpec to_spec(const Peer& peer);

// Normalized writing of a whitelist, read back by Whitelist::load_string.
// header: comment placed at the top, one comment line per line of text.
std::string to_yaml(const std::vector<PeerSpec>& peers, std::string_view header = {});

}  // namespace tlsrelay::whitelist
