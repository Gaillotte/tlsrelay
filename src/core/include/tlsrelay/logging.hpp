#pragma once

#include "tlsrelay/config.hpp"

#include <spdlog/spdlog.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>

// Journalisation (SPEC §9). Deux catégories : « activity » (connexions, canaux)
// et « config » (chargements, rechargements, opérations d'administration).
// Ne jamais y écrire de clé, de jeton ni de contenu relayé.
namespace tlsrelay::logging {

enum class Category { activity, config };

// Journalisation minimale (stderr, niveau info) utilisable avant le chargement
// de la configuration. Appelée implicitement au premier accès.
void init_default();

// Applique la configuration. cli_level, s'il est présent (-q, -v, -vv),
// remplace le niveau global et ceux des catégories.
// Lève std::runtime_error si la sortie ne peut pas être ouverte.
void init(const LogConfig& cfg, std::optional<LogLevel> cli_level = std::nullopt);

spdlog::logger& activity();
spdlog::logger& config();

void set_level(Category cat, LogLevel level);
LogLevel level(Category cat);

// « niveau » (les deux catégories) ou « catégorie=niveau ». Retourne un
// message d'erreur, vide en cas de succès.
std::string apply_level_spec(std::string_view spec);

// Rouvre le fichier de log (après une rotation externe). Faux si la sortie est stderr.
// Lève std::runtime_error si le fichier ne peut pas être rouvert (l'ancien reste utilisé).
bool reopen();

// Sortie courante : "stderr" ou chemin du fichier.
std::string output();

spdlog::level::level_enum to_spdlog(LogLevel level);

// Format JSON : une ligne par événement {"ts","level","cat","msg"}.
std::unique_ptr<spdlog::formatter> make_json_formatter();
std::string json_escape(std::string_view text);

}  // namespace tlsrelay::logging
