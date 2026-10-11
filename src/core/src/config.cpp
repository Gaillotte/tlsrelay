#include "tlsrelay/config.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <initializer_list>
#include <set>
#include <sstream>

namespace tlsrelay {

std::string_view to_string(Mode m) {
    return m == Mode::client ? "client" : "server";
}

std::string_view to_string(PortKind k) {
    switch (k) {
        case PortKind::plain: return "plain";
        case PortKind::tls: return "tls";
        case PortKind::mtls: return "mtls";
    }
    return "?";
}

std::string_view to_string(LogLevel l) {
    switch (l) {
        case LogLevel::error: return "error";
        case LogLevel::info: return "info";
        case LogLevel::debug: return "debug";
        case LogLevel::trace: return "trace";
    }
    return "?";
}

std::optional<LogLevel> parse_log_level(std::string_view text) {
    if (text == "error") return LogLevel::error;
    if (text == "info") return LogLevel::info;
    if (text == "debug") return LogLevel::debug;
    if (text == "trace") return LogLevel::trace;
    return std::nullopt;
}

namespace {

std::string join(const std::string& path, std::string_view key) {
    return path.empty() ? std::string(key) : path + "." + std::string(key);
}

// Lecture du YAML vers Config. Les erreurs de forme (clé inconnue, type,
// format de valeur) sont toutes collectées au lieu de s'arrêter à la première.
class Parser {
public:
    explicit Parser(std::vector<Issue>& errors) : errors_(errors) {}

    Config parse(const YAML::Node& root) {
        Config cfg;
        if (!is_map(root, "")) return cfg;
        check_keys(root, "", {"mode", "instance", "logging", "credentials", "limits", "ports",
                              "source_address", "destination", "whitelist", "admin"});

        if (auto v = required_string(root, "mode", "")) {
            if (*v == "client") cfg.mode = Mode::client;
            else if (*v == "server") cfg.mode = Mode::server;
            else error("mode", "valeur attendue : client ou server");
        }
        if (auto v = optional_string(root, "instance", "")) cfg.instance = *v;
        if (auto node = section(root, "logging", "")) cfg.logging = parse_logging(*node, "logging");
        if (auto node = section(root, "credentials", "")) cfg.credentials = parse_credentials(*node, "credentials");
        if (auto node = section(root, "limits", "")) cfg.limits = parse_limits(*node, "limits");
        if (auto node = section(root, "ports", "")) parse_ports(*node, "ports", cfg.ports);
        cfg.source_address = optional_string(root, "source_address", "");
        if (auto node = section(root, "destination", "")) cfg.destination = parse_destination(*node, "destination");
        if (auto node = section(root, "whitelist", "")) cfg.whitelist = parse_whitelist(*node, "whitelist");
        if (auto node = section(root, "admin", "")) cfg.admin = parse_admin(*node, "admin");
        return cfg;
    }

private:
    void error(const std::string& path, std::string message) {
        errors_.push_back({path, std::move(message)});
    }

    bool is_map(const YAML::Node& node, const std::string& path) {
        if (node.IsMap()) return true;
        error(path.empty() ? "(racine)" : path, "une section (liste de clés) est attendue");
        return false;
    }

    void check_keys(const YAML::Node& map, const std::string& path, std::initializer_list<std::string_view> allowed) {
        for (const auto& item : map) {
            const auto key = item.first.as<std::string>("");
            if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
                error(join(path, key), "clé inconnue");
            }
        }
    }

    std::optional<YAML::Node> section(const YAML::Node& map, std::string_view key, const std::string& path) {
        const YAML::Node node = map[std::string(key)];
        if (!node.IsDefined()) return std::nullopt;
        if (!is_map(node, join(path, key))) return std::nullopt;
        return node;
    }

    std::optional<std::string> optional_string(const YAML::Node& map, std::string_view key, const std::string& path) {
        const YAML::Node node = map[std::string(key)];
        if (!node.IsDefined()) return std::nullopt;
        if (!node.IsScalar()) {
            error(join(path, key), "une valeur simple est attendue");
            return std::nullopt;
        }
        return node.Scalar();
    }

    std::optional<std::string> required_string(const YAML::Node& map, std::string_view key, const std::string& path) {
        if (!map[std::string(key)].IsDefined()) {
            error(join(path, key), "valeur obligatoire manquante");
            return std::nullopt;
        }
        return optional_string(map, key, path);
    }

    void read_duration(const YAML::Node& map, std::string_view key, const std::string& path, Duration& out) {
        if (auto v = optional_string(map, key, path)) {
            if (auto d = parse_duration(*v)) out = *d;
            else error(join(path, key), "durée invalide « " + *v + " » (exemples : 500ms, 30s, 5m, 1h, 30d)");
        }
    }

    void read_size(const YAML::Node& map, std::string_view key, const std::string& path, std::uint64_t& out) {
        if (auto v = optional_string(map, key, path)) {
            if (auto s = parse_size(*v)) out = *s;
            else error(join(path, key), "taille invalide « " + *v + " » (exemples : 65536, 64KiB, 4MiB)");
        }
    }

    void read_percent(const YAML::Node& map, std::string_view key, const std::string& path, double& out) {
        if (auto v = optional_string(map, key, path)) {
            if (auto p = parse_percent(*v)) out = *p;
            else error(join(path, key), "pourcentage invalide « " + *v + " » (exemple : 10%)");
        }
    }

    void read_uint(const YAML::Node& map, std::string_view key, const std::string& path, std::uint32_t& out) {
        if (auto v = optional_string(map, key, path)) {
            std::uint32_t value = 0;
            auto [end, ec] = std::from_chars(v->data(), v->data() + v->size(), value);
            if (ec != std::errc{} || end != v->data() + v->size()) error(join(path, key), "entier positif attendu");
            else out = value;
        }
    }

    void read_bool(const YAML::Node& map, std::string_view key, const std::string& path, bool& out) {
        if (auto v = optional_string(map, key, path)) {
            if (*v == "true") out = true;
            else if (*v == "false") out = false;
            else error(join(path, key), "valeur attendue : true ou false");
        }
    }

    std::optional<Endpoint> read_endpoint(const YAML::Node& map, std::string_view key, const std::string& path) {
        auto v = optional_string(map, key, path);
        if (!v) return std::nullopt;
        auto ep = parse_endpoint(*v);
        if (!ep) error(join(path, key), "adresse invalide « " + *v + " » (format hôte:port, IPv6 entre crochets)");
        return ep;
    }

    std::optional<LogLevel> read_level(const YAML::Node& map, std::string_view key, const std::string& path) {
        auto v = optional_string(map, key, path);
        if (!v) return std::nullopt;
        auto level = parse_log_level(*v);
        if (!level) error(join(path, key), "niveau invalide (error, info, debug ou trace)");
        return level;
    }

    LogConfig parse_logging(const YAML::Node& node, const std::string& path) {
        LogConfig log;
        check_keys(node, path, {"level", "categories", "format", "output"});
        if (auto l = read_level(node, "level", path)) log.level = *l;
        if (auto cats = section(node, "categories", path)) {
            const auto cpath = join(path, "categories");
            check_keys(*cats, cpath, {"activity", "config"});
            log.activity = read_level(*cats, "activity", cpath);
            log.config = read_level(*cats, "config", cpath);
        }
        if (auto f = optional_string(node, "format", path)) {
            if (*f == "text") log.format = LogFormat::text;
            else if (*f == "json") log.format = LogFormat::json;
            else error(join(path, "format"), "valeur attendue : text ou json");
        }
        if (auto o = optional_string(node, "output", path)) log.output = *o;
        return log;
    }

    Credentials parse_credentials(const YAML::Node& node, const std::string& path) {
        Credentials c;
        check_keys(node, path, {"pki_root", "watch", "expiry_warning"});
        if (auto v = required_string(node, "pki_root", path)) c.pki_root = *v;
        read_bool(node, "watch", path, c.watch);
        read_duration(node, "expiry_warning", path, c.expiry_warning);
        return c;
    }

    Limits parse_limits(const YAML::Node& node, const std::string& path) {
        Limits l;
        check_keys(node, path, {"idle_timeout", "session_lifetime", "session_jitter", "renegotiation_grace",
                                "resume_buffer", "handshake_timeout", "max_channels", "shutdown_timeout"});
        read_duration(node, "idle_timeout", path, l.idle_timeout);
        read_duration(node, "session_lifetime", path, l.session_lifetime);
        read_percent(node, "session_jitter", path, l.session_jitter);
        read_duration(node, "renegotiation_grace", path, l.renegotiation_grace);
        read_size(node, "resume_buffer", path, l.resume_buffer);
        read_duration(node, "handshake_timeout", path, l.handshake_timeout);
        read_uint(node, "max_channels", path, l.max_channels);
        read_duration(node, "shutdown_timeout", path, l.shutdown_timeout);
        return l;
    }

    void parse_ports(const YAML::Node& node, const std::string& path, std::map<PortKind, PortConfig>& out) {
        check_keys(node, path, {"plain", "tls", "mtls"});
        for (PortKind kind : {PortKind::plain, PortKind::tls, PortKind::mtls}) {
            auto port = section(node, to_string(kind), path);
            if (!port) continue;
            const auto ppath = join(path, to_string(kind));
            check_keys(*port, ppath, {"listen", "upstream", "server_name"});
            PortConfig pc;
            if (!(*port)["listen"].IsDefined()) error(join(ppath, "listen"), "valeur obligatoire manquante");
            if (auto ep = read_endpoint(*port, "listen", ppath)) pc.listen = *ep;
            pc.upstream = read_endpoint(*port, "upstream", ppath);
            pc.server_name = optional_string(*port, "server_name", ppath);
            out[kind] = pc;
        }
    }

    Destination parse_destination(const YAML::Node& node, const std::string& path) {
        Destination d;
        check_keys(node, path, {"address", "port", "dial_timeout", "dial_retries", "dial_backoff"});
        if (auto a = required_string(node, "address", path)) d.endpoint.host = *a;
        std::uint32_t port = 0;
        if (!node["port"].IsDefined()) error(join(path, "port"), "valeur obligatoire manquante");
        read_uint(node, "port", path, port);
        if (port > 65535) error(join(path, "port"), "port hors de la plage 1–65535");
        else d.endpoint.port = static_cast<std::uint16_t>(port);
        read_duration(node, "dial_timeout", path, d.dial_timeout);
        read_uint(node, "dial_retries", path, d.dial_retries);
        read_duration(node, "dial_backoff", path, d.dial_backoff);
        return d;
    }

    AdminConfig parse_admin(const YAML::Node& node, const std::string& path) {
        AdminConfig a;
        check_keys(node, path, {"enabled", "endpoint"});
        read_bool(node, "enabled", path, a.enabled);
        a.endpoint = optional_string(node, "endpoint", path);
        return a;
    }

    WhitelistRef parse_whitelist(const YAML::Node& node, const std::string& path) {
        WhitelistRef w;
        check_keys(node, path, {"file", "revoke_mode"});
        if (auto f = required_string(node, "file", path)) w.file = *f;
        if (auto m = optional_string(node, "revoke_mode", path)) {
            if (*m == "immediate") w.revoke_mode = RevokeMode::immediate;
            else if (*m == "next_renegotiation") w.revoke_mode = RevokeMode::next_renegotiation;
            else error(join(path, "revoke_mode"), "valeur attendue : immediate ou next_renegotiation");
        }
        return w;
    }

    std::vector<Issue>& errors_;
};

}  // namespace

bool valid_instance_name(std::string_view name) {
    if (name.empty() || name.size() > 32) return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}

void validate(const Config& cfg, std::vector<Issue>& errors, std::vector<Issue>& warnings) {
    (void)warnings;  // aucun avertissement défini pour l'instant
    auto err = [&](std::string path, std::string message) { errors.push_back({std::move(path), std::move(message)}); };
    const bool client = cfg.mode == Mode::client;

    if (!valid_instance_name(cfg.instance)) {
        err("instance", "nom invalide : 1 à 32 caractères parmi lettres, chiffres, - et _");
    }
    if (cfg.admin.endpoint && cfg.admin.endpoint->empty()) err("admin.endpoint", "valeur vide");

    // Ports
    if (cfg.ports.empty()) err("ports", "aucun port configuré");
    for (const auto& [kind, port] : cfg.ports) {
        const auto path = "ports." + std::string(to_string(kind));
        if (port.listen.port == 0) err(path + ".listen", "port hors de la plage 1–65535");
        if (!is_ip_literal(port.listen.host)) err(path + ".listen", "l'adresse d'écoute doit être une adresse IP");
        if (client) {
            if (!port.upstream) err(path + ".upstream", "valeur obligatoire en mode client");
            else if (port.upstream->port == 0) err(path + ".upstream", "port hors de la plage 1–65535");
            if (port.server_name && kind == PortKind::plain) err(path + ".server_name", "sans objet pour le port plain");
        } else {
            if (port.upstream) err(path + ".upstream", "sans objet en mode serveur (utiliser destination)");
            if (port.server_name) err(path + ".server_name", "sans objet en mode serveur");
        }
    }
    // Deux ports ne peuvent pas écouter sur la même adresse ; une adresse joker
    // (0.0.0.0, ::) entre en conflit avec toute adresse sur le même port.
    for (auto a = cfg.ports.begin(); a != cfg.ports.end(); ++a) {
        for (auto b = std::next(a); b != cfg.ports.end(); ++b) {
            const auto& la = a->second.listen;
            const auto& lb = b->second.listen;
            if (la.port != lb.port || la.port == 0) continue;
            if (la.host == lb.host || is_wildcard_address(la.host) || is_wildcard_address(lb.host)) {
                err("ports." + std::string(to_string(b->first)) + ".listen",
                    "même adresse d'écoute que ports." + std::string(to_string(a->first)));
            }
        }
    }

    const bool uses_tls = cfg.ports.count(PortKind::tls) != 0 || cfg.ports.count(PortKind::mtls) != 0;
    if (uses_tls && (!cfg.credentials || cfg.credentials->pki_root.empty())) {
        err("credentials.pki_root", "obligatoire quand un port tls ou mtls est configuré");
    }

    // Mode client / serveur
    if (client) {
        if (cfg.destination) err("destination", "sans objet en mode client");
        if (cfg.whitelist) err("whitelist", "sans objet en mode client");
        if (cfg.source_address && !is_ip_literal(*cfg.source_address)) {
            err("source_address", "adresse IP attendue");
        }
    } else {
        if (cfg.source_address) err("source_address", "sans objet en mode serveur");
        if (!cfg.destination) {
            err("destination", "obligatoire en mode serveur");
        } else {
            const auto& d = *cfg.destination;
            if (d.endpoint.host.empty()) err("destination.address", "valeur obligatoire");
            if (d.endpoint.port == 0) err("destination.port", "port hors de la plage 1–65535");
            if (d.dial_timeout.count() <= 0) err("destination.dial_timeout", "doit être supérieur à 0");
            if (d.dial_retries < 1 || d.dial_retries > 10) err("destination.dial_retries", "doit être compris entre 1 et 10");
        }
        if (!cfg.whitelist) err("whitelist", "obligatoire en mode serveur");
        else if (cfg.whitelist->file.empty()) err("whitelist.file", "valeur obligatoire");
    }

    // Limites (SPEC §5.2)
    const auto& l = cfg.limits;
    if (l.idle_timeout.count() <= 0) err("limits.idle_timeout", "doit être supérieur à 0");
    if (l.session_lifetime.count() <= 0) err("limits.session_lifetime", "doit être supérieur à 0");
    if (l.idle_timeout >= l.session_lifetime) err("limits.idle_timeout", "doit être inférieur à limits.session_lifetime");
    if (l.renegotiation_grace * 2 >= l.session_lifetime) {
        err("limits.renegotiation_grace", "doit être inférieur à la moitié de limits.session_lifetime");
    }
    if (l.session_jitter > 0.5) err("limits.session_jitter", "ne doit pas dépasser 50%");
    if (l.resume_buffer < (64ULL << 10)) err("limits.resume_buffer", "doit être au moins 64KiB");
    if (l.handshake_timeout.count() <= 0) err("limits.handshake_timeout", "doit être supérieur à 0");
    if (l.max_channels < 1 || l.max_channels > 100000) err("limits.max_channels", "doit être compris entre 1 et 100000");
    if (l.shutdown_timeout.count() < 0) err("limits.shutdown_timeout", "ne doit pas être négatif");

    // Journalisation
    if (cfg.logging.output.empty()) {
        err("logging.output", "valeur obligatoire (stderr ou chemin de fichier)");
    } else if (cfg.logging.output == "syslog" || cfg.logging.output == "eventlog") {
        err("logging.output", "« " + cfg.logging.output + " » n'est pas encore pris en charge par cette version");
    }
}

LoadResult load_config_string(std::string_view yaml) {
    LoadResult result;
    YAML::Node root;
    try {
        root = YAML::Load(std::string(yaml));
    } catch (const YAML::Exception& e) {
        std::ostringstream where;
        where << "ligne " << (e.mark.line + 1) << ", colonne " << (e.mark.column + 1);
        result.errors.push_back({where.str(), "syntaxe YAML invalide : " + e.msg});
        return result;
    }

    Parser parser(result.errors);
    Config cfg = parser.parse(root);
    if (!result.errors.empty()) return result;

    validate(cfg, result.errors, result.warnings);
    if (result.errors.empty()) result.config = std::move(cfg);
    return result;
}

LoadResult load_config_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        LoadResult result;
        result.errors.push_back({path.string(), "fichier illisible"});
        return result;
    }
    std::ostringstream text;
    text << in.rdbuf();
    return load_config_string(text.str());
}

}  // namespace tlsrelay
