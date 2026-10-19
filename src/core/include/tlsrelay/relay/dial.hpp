#pragma once

#include "tlsrelay/endpoint.hpp"
#include "tlsrelay/relay/stats.hpp"
#include "tlsrelay/units.hpp"

#include <asio/awaitable.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>

#include <cstdint>
#include <optional>
#include <system_error>

namespace tlsrelay::relay {

struct DialOptions {
    Endpoint target;
    std::optional<asio::ip::address> source;  // imposed source address (client mode)
    Duration timeout{};                       // per attempt and per resolved address
    std::uint32_t attempts = 1;
    Duration backoff{};                       // wait before the 2nd attempt, doubled afterwards
};

// Opens an outgoing TCP connection, with successive attempts (SPEC §5.4).
// Returns std::nullopt if all attempts fail or if the operation is cancelled;
// last_error, if given, receives the error of the last attempt.
asio::awaitable<std::optional<asio::ip::tcp::socket>> dial(DialOptions options, std::uint64_t channel_id, Stats& stats,
                                                           std::error_code* last_error = nullptr);

}  // namespace tlsrelay::relay
