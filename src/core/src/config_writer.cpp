#include "tlsrelay/config.hpp"

#include <yaml-cpp/yaml.h>

#include <sstream>

namespace tlsrelay {
namespace {

// Header comment: each line prefixed with "#".
std::string comment_block(std::string_view header) {
    std::string out;
    std::istringstream lines{std::string(header)};
    for (std::string line; std::getline(lines, line);) out += line.empty() ? "#\n" : "# " + line + "\n";
    return out;
}

// Adds a key to the current section if the value differs from the default.
template <typename T, typename Format>
void put_if(YAML::Emitter& out, const char* key, const T& value, const T& fallback, Format format) {
    if (value == fallback) return;
    out << YAML::Key << key << YAML::Value << format(value);
}

std::string text_of(const std::string& s) { return s; }
std::string bool_text(bool b) { return b ? "true" : "false"; }

void write_logging(YAML::Emitter& out, const LogConfig& log) {
    const LogConfig defaults;
    if (log == defaults) return;
    out << YAML::Key << "logging" << YAML::Value << YAML::BeginMap;
    put_if(out, "level", log.level, defaults.level, [](LogLevel l) { return std::string(to_string(l)); });
    if (log.activity || log.config) {
        out << YAML::Key << "categories" << YAML::Value << YAML::BeginMap;
        if (log.activity) out << YAML::Key << "activity" << YAML::Value << std::string(to_string(*log.activity));
        if (log.config) out << YAML::Key << "config" << YAML::Value << std::string(to_string(*log.config));
        out << YAML::EndMap;
    }
    put_if(out, "format", log.format, defaults.format,
           [](LogFormat f) { return std::string(f == LogFormat::json ? "json" : "text"); });
    put_if(out, "output", log.output, defaults.output, text_of);
    out << YAML::EndMap;
}

void write_credentials(YAML::Emitter& out, const Credentials& c) {
    const Credentials defaults;
    out << YAML::Key << "credentials" << YAML::Value << YAML::BeginMap;
    out << YAML::Key << "pki_root" << YAML::Value << c.pki_root;
    put_if(out, "watch", c.watch, defaults.watch, bool_text);
    put_if(out, "expiry_warning", c.expiry_warning, defaults.expiry_warning, format_duration);
    out << YAML::EndMap;
}

void write_limits(YAML::Emitter& out, const Limits& l) {
    const Limits d;
    if (l == d) return;
    out << YAML::Key << "limits" << YAML::Value << YAML::BeginMap;
    put_if(out, "idle_timeout", l.idle_timeout, d.idle_timeout, format_duration);
    put_if(out, "session_lifetime", l.session_lifetime, d.session_lifetime, format_duration);
    put_if(out, "session_jitter", l.session_jitter, d.session_jitter, format_percent);
    put_if(out, "renegotiation_grace", l.renegotiation_grace, d.renegotiation_grace, format_duration);
    put_if(out, "resume_buffer", l.resume_buffer, d.resume_buffer, format_size);
    put_if(out, "handshake_timeout", l.handshake_timeout, d.handshake_timeout, format_duration);
    put_if(out, "keepalive_interval", l.keepalive_interval, d.keepalive_interval, format_duration);
    put_if(out, "max_channels", l.max_channels, d.max_channels, [](std::uint32_t n) { return std::to_string(n); });
    put_if(out, "shutdown_timeout", l.shutdown_timeout, d.shutdown_timeout, format_duration);
    out << YAML::EndMap;
}

void write_ports(YAML::Emitter& out, const std::map<PortKind, PortConfig>& ports) {
    out << YAML::Key << "ports" << YAML::Value << YAML::BeginMap;
    for (const auto& [kind, port] : ports) {
        out << YAML::Key << std::string(to_string(kind)) << YAML::Value << YAML::BeginMap;
        out << YAML::Key << "listen" << YAML::Value << port.listen.to_string();
        if (port.upstream) out << YAML::Key << "upstream" << YAML::Value << port.upstream->to_string();
        if (port.server_name) out << YAML::Key << "server_name" << YAML::Value << *port.server_name;
        out << YAML::EndMap;
    }
    out << YAML::EndMap;
}

void write_destination(YAML::Emitter& out, const Destination& dest) {
    const Destination d;
    out << YAML::Key << "destination" << YAML::Value << YAML::BeginMap;
    out << YAML::Key << "address" << YAML::Value << dest.endpoint.host;
    out << YAML::Key << "port" << YAML::Value << std::to_string(dest.endpoint.port);
    put_if(out, "dial_timeout", dest.dial_timeout, d.dial_timeout, format_duration);
    put_if(out, "dial_retries", dest.dial_retries, d.dial_retries, [](std::uint32_t n) { return std::to_string(n); });
    put_if(out, "dial_backoff", dest.dial_backoff, d.dial_backoff, format_duration);
    out << YAML::EndMap;
}

void write_whitelist(YAML::Emitter& out, const WhitelistRef& w) {
    out << YAML::Key << "whitelist" << YAML::Value << YAML::BeginMap;
    out << YAML::Key << "file" << YAML::Value << w.file;
    put_if(out, "revoke_mode", w.revoke_mode, RevokeMode::immediate, [](RevokeMode m) {
        return std::string(m == RevokeMode::immediate ? "immediate" : "next_renegotiation");
    });
    out << YAML::EndMap;
}

void write_admin(YAML::Emitter& out, const AdminConfig& a) {
    const AdminConfig d;
    if (a == d) return;
    out << YAML::Key << "admin" << YAML::Value << YAML::BeginMap;
    put_if(out, "enabled", a.enabled, d.enabled, bool_text);
    if (a.endpoint) out << YAML::Key << "endpoint" << YAML::Value << *a.endpoint;
    out << YAML::EndMap;
}

}  // namespace

std::string to_yaml(const Config& cfg, std::string_view header) {
    YAML::Emitter out;
    out.SetIndent(2);
    out << YAML::BeginMap;
    out << YAML::Key << "mode" << YAML::Value << std::string(to_string(cfg.mode));
    out << YAML::Key << "instance" << YAML::Value << cfg.instance;
    write_logging(out, cfg.logging);
    if (cfg.credentials) write_credentials(out, *cfg.credentials);
    write_limits(out, cfg.limits);
    if (!cfg.ports.empty()) write_ports(out, cfg.ports);
    if (cfg.source_address) out << YAML::Key << "source_address" << YAML::Value << *cfg.source_address;
    if (cfg.destination) write_destination(out, *cfg.destination);
    if (cfg.whitelist) write_whitelist(out, *cfg.whitelist);
    write_admin(out, cfg.admin);
    out << YAML::EndMap;
    if (!out.good()) throw std::runtime_error("cannot write YAML: " + out.GetLastError());
    return comment_block(header) + out.c_str() + "\n";
}

}  // namespace tlsrelay
