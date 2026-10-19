#pragma once

#include "common.hpp"

#include <optional>

namespace testkit {

struct ProxyOptions {
    Clock::duration delay{};      // latency added per relayed packet, in each direction
    double rate_mbps = 0;         // maximum throughput per direction and per connection (0: unlimited)
    Clock::duration cut_every{};  // periodic cut of all connections (0: never)
    bool freeze = false;          // at each deadline, silent link instead of a cut
    std::optional<asio::ip::address> source;  // source address of the connections to the destination
};

// TCP relay with disturbances (until Ctrl+C).
int run_proxy(const tcp::endpoint& listen, const tcp::endpoint& target, const ProxyOptions& options, unsigned threads);

}  // namespace testkit
