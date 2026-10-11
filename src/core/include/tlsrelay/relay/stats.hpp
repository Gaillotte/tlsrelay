#pragma once

#include <atomic>
#include <cstdint>

namespace tlsrelay::relay {

// Compteurs cumulés depuis le démarrage. Base des métriques (phase 6).
struct Stats {
    std::atomic<std::uint64_t> channels_opened{0};
    std::atomic<std::uint64_t> channels_closed{0};
    std::atomic<std::uint64_t> channels_rejected{0};     // limite max_channels atteinte
    std::atomic<std::uint64_t> channels_idle_closed{0};  // fermés par idle_timeout
    std::atomic<std::uint64_t> dial_attempt_failures{0}; // essais de connexion sortante échoués
    std::atomic<std::uint64_t> dial_failures{0};         // canaux abandonnés après tous les essais
    std::atomic<std::uint64_t> tls_handshake_failures{0}; // handshakes TLS refusés ou expirés
    std::atomic<std::uint64_t> peers_rejected{0};        // pairs refusés par la liste blanche
    std::atomic<std::uint64_t> peers_revoked{0};         // canaux fermés après retrait du pair de la liste
    std::atomic<std::uint64_t> pki_rotations{0};         // bascules vers une nouvelle génération PKI
    std::atomic<std::uint64_t> pki_reload_failures{0};   // nouvelles générations refusées
    std::atomic<std::uint64_t> renegotiations{0};        // reprises de session réussies (connexion n+1)
    std::atomic<std::uint64_t> resume_failures{0};       // reprises refusées ou échouées
    std::atomic<std::uint64_t> protocol_errors{0};       // trames non conformes reçues
    std::atomic<std::uint64_t> bytes_upstream{0};        // application -> destination
    std::atomic<std::uint64_t> bytes_downstream{0};      // destination -> application
};

}  // namespace tlsrelay::relay
