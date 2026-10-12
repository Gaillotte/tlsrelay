#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tlsrelay {

using Duration = std::chrono::milliseconds;

// Durée au format <entier><unité>, unités : ms, s, m, h, d. Exemple : "30s", "5m".
std::optional<Duration> parse_duration(std::string_view text);

// Taille au format <entier>[unité], unités : B, KiB, MiB, GiB. Sans unité : octets.
std::optional<std::uint64_t> parse_size(std::string_view text);

// Pourcentage au format <nombre>%, entre 0 et 100. Retourne une fraction (10% -> 0.1).
std::optional<double> parse_percent(std::string_view text);

// Forme lisible d'une durée, avec l'unité la plus grande qui la représente exactement.
std::string format_duration(Duration d);

// Forme lisible d'une taille, avec l'unité la plus grande qui la représente exactement ("4MiB").
std::string format_size(std::uint64_t bytes);

// Forme lisible d'une fraction en pourcentage (0.1 -> "10%"), relue à l'identique par parse_percent.
std::string format_percent(double fraction);

}  // namespace tlsrelay
