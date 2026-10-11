#include "tlsrelay/logging.hpp"

#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/dist_sink.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <cstdio>
#include <ctime>
#include <mutex>
#include <stdexcept>

namespace tlsrelay::logging {
namespace {

constexpr const char* kTextPattern = "%Y-%m-%dT%H:%M:%S.%eZ %-5l [%n] %v";

struct State {
    std::mutex mutex;
    std::shared_ptr<spdlog::logger> activity;
    std::shared_ptr<spdlog::logger> config;
    // Les journaux écrivent dans dist, dont la sortie réelle peut être remplacée
    // à chaud (réouverture du fichier) sans toucher aux loggers.
    std::shared_ptr<spdlog::sinks::dist_sink_mt> dist;
    LogConfig cfg;
};

State& state() {
    static State s;
    return s;
}

std::string iso_utc(spdlog::log_clock::time_point tp) {
    const auto t = spdlog::log_clock::to_time_t(tp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char base[32];
    (void)std::strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tm);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count() % 1000;
    char out[48];
    (void)std::snprintf(out, sizeof out, "%s.%03dZ", base, static_cast<int>(ms));
    return out;
}

class JsonFormatter final : public spdlog::formatter {
public:
    void format(const spdlog::details::log_msg& msg, spdlog::memory_buf_t& dest) override {
        const auto level = spdlog::level::to_string_view(msg.level);
        std::string line;
        line.reserve(96 + msg.payload.size());
        line += "{\"ts\":\"";
        line += iso_utc(msg.time);
        line += "\",\"level\":\"";
        line.append(level.data(), level.size());
        line += "\",\"cat\":\"";
        line += json_escape(std::string_view(msg.logger_name.data(), msg.logger_name.size()));
        line += "\",\"msg\":\"";
        line += json_escape(std::string_view(msg.payload.data(), msg.payload.size()));
        line += "\"}\n";
        dest.append(line.data(), line.data() + line.size());
    }

    std::unique_ptr<spdlog::formatter> clone() const override { return std::make_unique<JsonFormatter>(); }
};

std::shared_ptr<spdlog::logger> make_logger(const std::string& name, spdlog::sink_ptr sink, spdlog::level::level_enum level) {
    auto logger = std::make_shared<spdlog::logger>(name, std::move(sink));
    logger->set_level(level);
    logger->flush_on(spdlog::level::trace);
    return logger;
}

spdlog::sink_ptr make_output(const LogConfig& cfg) {
    spdlog::sink_ptr sink;
    if (cfg.output == "stderr") {
        sink = std::make_shared<spdlog::sinks::stderr_sink_mt>();
    } else {
        try {
            sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(cfg.output, false);
        } catch (const spdlog::spdlog_ex& e) {
            throw std::runtime_error("impossible d'ouvrir le fichier de log « " + cfg.output + " » : " + e.what());
        }
    }
    if (cfg.format == LogFormat::json) sink->set_formatter(make_json_formatter());
    else sink->set_formatter(std::make_unique<spdlog::pattern_formatter>(kTextPattern, spdlog::pattern_time_type::utc));
    return sink;
}

void install_default_locked(State& s) {
    s.cfg = LogConfig{};
    s.dist = std::make_shared<spdlog::sinks::dist_sink_mt>();
    s.dist->add_sink(make_output(s.cfg));
    s.activity = make_logger("activity", s.dist, spdlog::level::info);
    s.config = make_logger("config", s.dist, spdlog::level::info);
}

spdlog::logger& get(std::shared_ptr<spdlog::logger> State::*member) {
    auto& s = state();
    std::lock_guard lock(s.mutex);
    if (!(s.*member)) install_default_locked(s);
    return *(s.*member);
}

}  // namespace

spdlog::level::level_enum to_spdlog(LogLevel level) {
    switch (level) {
        case LogLevel::error: return spdlog::level::err;
        case LogLevel::info: return spdlog::level::info;
        case LogLevel::debug: return spdlog::level::debug;
        case LogLevel::trace: return spdlog::level::trace;
    }
    return spdlog::level::info;
}

void init_default() {
    auto& s = state();
    std::lock_guard lock(s.mutex);
    install_default_locked(s);
}

void init(const LogConfig& cfg, std::optional<LogLevel> cli_level) {
    auto sink = make_output(cfg);
    const LogLevel activity_level = cli_level.value_or(cfg.activity.value_or(cfg.level));
    const LogLevel config_level = cli_level.value_or(cfg.config.value_or(cfg.level));

    auto& s = state();
    std::lock_guard lock(s.mutex);
    s.cfg = cfg;
    s.dist = std::make_shared<spdlog::sinks::dist_sink_mt>();
    s.dist->add_sink(std::move(sink));
    s.activity = make_logger("activity", s.dist, to_spdlog(activity_level));
    s.config = make_logger("config", s.dist, to_spdlog(config_level));
}

bool reopen() {
    auto& s = state();
    std::lock_guard lock(s.mutex);
    if (!s.dist || s.cfg.output == "stderr") return false;
    // Le fichier courant est fermé par set_sinks après l'ouverture du nouveau.
    s.dist->set_sinks({make_output(s.cfg)});
    return true;
}

std::string output() {
    auto& s = state();
    std::lock_guard lock(s.mutex);
    return s.cfg.output;
}

LogLevel level(Category cat) {
    const auto l = (cat == Category::activity ? activity() : config()).level();
    if (l <= spdlog::level::trace) return LogLevel::trace;
    if (l <= spdlog::level::debug) return LogLevel::debug;
    if (l <= spdlog::level::info) return LogLevel::info;
    return LogLevel::error;
}

std::string apply_level_spec(std::string_view spec) {
    const auto eq = spec.find('=');
    const auto level_text = eq == std::string_view::npos ? spec : spec.substr(eq + 1);
    const auto parsed = parse_log_level(level_text);
    if (!parsed) return "niveau inconnu « " + std::string(level_text) + " » (error, info, debug ou trace)";
    if (eq == std::string_view::npos) {
        set_level(Category::activity, *parsed);
        set_level(Category::config, *parsed);
        return {};
    }
    const auto cat = spec.substr(0, eq);
    if (cat == "activity") set_level(Category::activity, *parsed);
    else if (cat == "config") set_level(Category::config, *parsed);
    else return "catégorie inconnue « " + std::string(cat) + " » (activity ou config)";
    return {};
}

spdlog::logger& activity() { return get(&State::activity); }
spdlog::logger& config() { return get(&State::config); }

void set_level(Category cat, LogLevel level) {
    (cat == Category::activity ? activity() : config()).set_level(to_spdlog(level));
}

std::unique_ptr<spdlog::formatter> make_json_formatter() { return std::make_unique<JsonFormatter>(); }

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    (void)std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += ch;
                }
        }
    }
    return out;
}

}  // namespace tlsrelay::logging
