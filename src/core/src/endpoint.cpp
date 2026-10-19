#include "tlsrelay/endpoint.hpp"

#include <asio/ip/address.hpp>

#include <charconv>

namespace tlsrelay {

std::string Endpoint::to_string() const {
    const bool v6 = host.find(':') != std::string::npos;
    return (v6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
}

std::optional<Endpoint> parse_endpoint(std::string_view text) {
    std::string_view host;
    std::string_view port;

    if (!text.empty() && text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':') return std::nullopt;
        host = text.substr(1, close - 1);
        port = text.substr(close + 2);
        if (!is_ip_literal(host) || host.find(':') == std::string_view::npos) return std::nullopt;
    } else {
        const auto colon = text.rfind(':');
        if (colon == std::string_view::npos) return std::nullopt;
        host = text.substr(0, colon);
        port = text.substr(colon + 1);
        // An IPv6 must be in brackets.
        if (host.find(':') != std::string_view::npos) return std::nullopt;
    }
    if (host.empty() || port.empty()) return std::nullopt;

    unsigned value = 0;
    auto [end, ec] = std::from_chars(port.data(), port.data() + port.size(), value);
    if (ec != std::errc{} || end != port.data() + port.size() || value > 65535) return std::nullopt;

    return Endpoint{std::string(host), static_cast<std::uint16_t>(value)};
}

bool is_ip_literal(std::string_view host) {
    std::error_code ec;
    asio::ip::make_address(std::string(host), ec);
    return !ec;
}

bool is_wildcard_address(std::string_view host) {
    std::error_code ec;
    const auto addr = asio::ip::make_address(std::string(host), ec);
    return !ec && addr.is_unspecified();
}

}  // namespace tlsrelay
