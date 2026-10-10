#pragma once

#include "tlsrelay/endpoint.hpp"
#include "tlsrelay/relay/stats.hpp"
#include "tlsrelay/units.hpp"

#include <asio/awaitable.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>

#include <cstdint>
#include <optional>

namespace tlsrelay::relay {

struct DialOptions {
    Endpoint target;
    std::optional<asio::ip::address> source;  // adresse source imposée (mode client)
    Duration timeout{};                       // par essai et par adresse résolue
    std::uint32_t attempts = 1;
    Duration backoff{};                       // attente avant le 2e essai, doublée ensuite
};

// Ouvre une connexion TCP sortante, avec essais successifs (SPEC §5.4).
// Retourne std::nullopt si tous les essais échouent ou si l'opération est annulée.
asio::awaitable<std::optional<asio::ip::tcp::socket>> dial(DialOptions options, std::uint64_t channel_id, Stats& stats);

}  // namespace tlsrelay::relay
