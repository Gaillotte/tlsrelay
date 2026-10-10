#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tlsrelay {

// Adresse réseau sous la forme hôte:port. L'hôte peut être un nom, une IPv4,
// ou une IPv6 entre crochets ("[::1]:9001").
struct Endpoint {
    std::string host;
    std::uint16_t port = 0;

    std::string to_string() const;
    bool operator==(const Endpoint&) const = default;
};

// Le port 0 est accepté ici ; la validation de la configuration impose 1–65535.
std::optional<Endpoint> parse_endpoint(std::string_view text);

// Vrai si le texte est une adresse IPv4 ou IPv6 littérale (sans crochets).
bool is_ip_literal(std::string_view host);

// Vrai pour 0.0.0.0 et ::.
bool is_wildcard_address(std::string_view host);

}  // namespace tlsrelay
