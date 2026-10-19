#pragma once

#include "common.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace testkit {

tcp::endpoint resolve(const std::string& host, std::uint16_t port);

// Echo destination (until Ctrl+C). By default, reading continues while
// writing; half_duplex: stops reading until the reply is written.
int run_echo(const tcp::endpoint& listen, unsigned threads, bool half_duplex = false);

struct LoadOptions {
    int channels = 100;
    std::uint64_t bytes = 1 << 20;      // per channel, in each direction
    int batch = 200;                    // channels opened per wave (0: all at once)
    std::chrono::milliseconds hold{0};  // keep all channels open before the transfer
    unsigned threads = 0;
    bool json = false;
};

// Opens all channels (one-byte round trip on each), then transfers
// bytes bytes in each direction per channel and compares the SHA-256 hashes.
// Exit code 0 if all channels are intact.
int run_load(const tcp::endpoint& target, const LoadOptions& options);

// Sustained throughput for duration over channels channels; rate_mbps > 0: send
// rate of each channel limited (Mbit/s).
int run_throughput(const tcp::endpoint& target, int channels, std::chrono::milliseconds duration, unsigned threads, bool json,
                   double rate_mbps = 0);

// Round trip of messages of size bytes, one after the other.
int run_latency(const tcp::endpoint& target, int count, std::size_t size, bool json);

}  // namespace testkit
