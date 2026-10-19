#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tlsrelay {

// Network address in the form host:port. The host can be a name, an IPv4,
// or an IPv6 in brackets ("[::1]:9001").
struct Endpoint {
    std::string host;
    std::uint16_t port = 0;

    std::string to_string() const;
    bool operator==(const Endpoint&) const = default;
};

// Port 0 is accepted here; configuration validation requires 1–65535.
std::optional<Endpoint> parse_endpoint(std::string_view text);

// True if the text is a literal IPv4 or IPv6 address (without brackets).
bool is_ip_literal(std::string_view host);

// True for 0.0.0.0 and ::.
bool is_wildcard_address(std::string_view host);

}  // namespace tlsrelay
