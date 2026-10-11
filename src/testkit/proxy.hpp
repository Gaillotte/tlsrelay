#pragma once

#include "common.hpp"

namespace testkit {

struct ProxyOptions {
    Clock::duration delay{};      // latence ajoutée par paquet relayé, dans chaque sens
    double rate_mbps = 0;         // débit maximal par sens et par connexion (0 : illimité)
    Clock::duration cut_every{};  // coupure périodique de toutes les connexions (0 : jamais)
    bool freeze = false;          // à chaque échéance, lien muet au lieu d'une coupure
};

// Relais TCP avec perturbations (jusqu'à Ctrl+C).
int run_proxy(const tcp::endpoint& listen, const tcp::endpoint& target, const ProxyOptions& options, unsigned threads);

}  // namespace testkit
