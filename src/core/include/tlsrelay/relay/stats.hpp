#pragma once

#include <atomic>
#include <cstdint>

namespace tlsrelay::relay {

// Counters accumulated since startup. Basis of the metrics (phase 6).
struct Stats {
    std::atomic<std::uint64_t> channels_opened{0};
    std::atomic<std::uint64_t> channels_closed{0};
    std::atomic<std::uint64_t> channels_rejected{0};     // max_channels limit reached
    std::atomic<std::uint64_t> channels_idle_closed{0};  // closed by idle_timeout
    std::atomic<std::uint64_t> dial_attempt_failures{0}; // failed outgoing connection attempts
    std::atomic<std::uint64_t> dial_failures{0};         // channels abandoned after all attempts
    std::atomic<std::uint64_t> tls_handshake_failures{0}; // TLS handshakes refused or timed out
    std::atomic<std::uint64_t> peers_rejected{0};        // peers refused by the whitelist
    std::atomic<std::uint64_t> peers_revoked{0};         // channels closed after removal of the peer from the whitelist
    std::atomic<std::uint64_t> certificates_revoked{0};  // channels closed after revocation of the peer certificate (CRL)
    std::atomic<std::uint64_t> crl_reload_failures{0};   // CRL files refused
    std::atomic<std::uint64_t> pki_rotations{0};         // switches to a new PKI generation
    std::atomic<std::uint64_t> pki_reload_failures{0};   // new generations refused
    std::atomic<std::uint64_t> renegotiations{0};        // successful session resumptions (connection n+1)
    std::atomic<std::uint64_t> resume_failures{0};       // resumptions refused or failed
    std::atomic<std::uint64_t> protocol_errors{0};       // malformed frames received
    std::atomic<std::uint64_t> bytes_upstream{0};        // application -> destination
    std::atomic<std::uint64_t> bytes_downstream{0};      // destination -> application
};

}  // namespace tlsrelay::relay
