#pragma once

#include "common.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace testkit {

tcp::endpoint resolve(const std::string& host, std::uint16_t port);

// Destination d'écho (jusqu'à Ctrl+C). Par défaut, la lecture continue pendant
// l'écriture ; half_duplex : ne lit plus tant que la réponse n'est pas écrite.
int run_echo(const tcp::endpoint& listen, unsigned threads, bool half_duplex = false);

struct LoadOptions {
    int channels = 100;
    std::uint64_t bytes = 1 << 20;      // par canal, dans chaque sens
    int batch = 200;                    // canaux ouverts par vague (0 : tous d'un coup)
    std::chrono::milliseconds hold{0};  // maintien de tous les canaux ouverts avant le transfert
    unsigned threads = 0;
    bool json = false;
};

// Ouvre tous les canaux (aller-retour d'un octet sur chacun), puis transfère
// bytes octets dans chaque sens par canal et compare les empreintes SHA-256.
// Code de sortie 0 si tous les canaux sont intègres.
int run_load(const tcp::endpoint& target, const LoadOptions& options);

// Débit soutenu pendant duration sur channels canaux ; rate_mbps > 0 : débit
// d'émission de chaque canal limité (Mbit/s).
int run_throughput(const tcp::endpoint& target, int channels, std::chrono::milliseconds duration, unsigned threads, bool json,
                   double rate_mbps = 0);

// Aller-retour de messages de size octets, l'un après l'autre.
int run_latency(const tcp::endpoint& target, int count, std::size_t size, bool json);

}  // namespace testkit
