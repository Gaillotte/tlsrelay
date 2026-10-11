#pragma once

#include "tlsrelay/endpoint.hpp"
#include "tlsrelay/units.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tlsrelay {

enum class Mode { client, server };
enum class PortKind { plain, tls, mtls };
enum class LogLevel { error, info, debug, trace };
enum class LogFormat { text, json };
enum class RevokeMode { immediate, next_renegotiation };

std::string_view to_string(Mode m);
std::string_view to_string(PortKind k);
std::string_view to_string(LogLevel l);
std::optional<LogLevel> parse_log_level(std::string_view text);

struct LogConfig {
    LogLevel level = LogLevel::info;
    std::optional<LogLevel> activity;  // surcharge du niveau pour la catégorie activity
    std::optional<LogLevel> config;    // surcharge du niveau pour la catégorie config
    LogFormat format = LogFormat::text;
    std::string output = "stderr";     // "stderr" ou chemin de fichier

    bool operator==(const LogConfig&) const = default;
};

struct Credentials {
    std::string pki_root;
    bool watch = true;
    Duration expiry_warning = std::chrono::days(30);

    bool operator==(const Credentials&) const = default;
};

struct Limits {
    Duration idle_timeout = std::chrono::minutes(5);
    Duration session_lifetime = std::chrono::hours(1);
    double session_jitter = 0.10;
    Duration renegotiation_grace = std::chrono::seconds(30);
    std::uint64_t resume_buffer = 4ULL << 20;
    Duration handshake_timeout = std::chrono::seconds(10);
    std::uint32_t max_channels = 5000;
    Duration shutdown_timeout = std::chrono::seconds(30);

    bool operator==(const Limits&) const = default;
};

struct PortConfig {
    Endpoint listen;
    std::optional<Endpoint> upstream;        // mode client uniquement
    std::optional<std::string> server_name;  // mode client, ports tls et mtls

    bool operator==(const PortConfig&) const = default;
};

struct Destination {
    Endpoint endpoint;
    Duration dial_timeout = std::chrono::seconds(5);
    std::uint32_t dial_retries = 3;
    Duration dial_backoff = std::chrono::seconds(1);

    bool operator==(const Destination&) const = default;
};

struct WhitelistRef {
    std::string file;
    RevokeMode revoke_mode = RevokeMode::immediate;

    bool operator==(const WhitelistRef&) const = default;
};

// Canal d'administration (SPEC §10) : socket Unix ou named pipe.
struct AdminConfig {
    bool enabled = true;
    std::optional<std::string> endpoint;  // défaut : default_admin_endpoint(instance)

    bool operator==(const AdminConfig&) const = default;
};

struct Config {
    Mode mode = Mode::client;
    std::string instance = "default";
    LogConfig logging;
    std::optional<Credentials> credentials;
    Limits limits;
    std::map<PortKind, PortConfig> ports;
    std::optional<std::string> source_address;  // mode client
    std::optional<Destination> destination;     // mode serveur
    std::optional<WhitelistRef> whitelist;      // mode serveur
    AdminConfig admin;
};

bool valid_instance_name(std::string_view name);

// Problème détecté dans une configuration. path suit la structure du YAML,
// par exemple "ports.plain.listen".
struct Issue {
    std::string path;
    std::string message;
};

struct LoadResult {
    std::optional<Config> config;  // présent seulement si errors est vide
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

LoadResult load_config_string(std::string_view yaml);
LoadResult load_config_file(const std::filesystem::path& path);

// Règles de cohérence (SPEC §8.3). Partagées avec l'éditeur tlsrelay-admin.
void validate(const Config& cfg, std::vector<Issue>& errors, std::vector<Issue>& warnings);

}  // namespace tlsrelay
