#pragma once

#include "tlsrelay/config.hpp"

#include <spdlog/spdlog.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>

// Logging (SPEC §9). Two categories: "activity" (connections, channels)
// and "config" (loads, reloads, administration operations).
// Never write keys, tokens or relayed content to them.
namespace tlsrelay::logging {

enum class Category { activity, config };

// Minimal logging (stderr, info level) usable before the configuration
// is loaded. Called implicitly on first access.
void init_default();

// Applies the configuration. cli_level, if present (-q, -v, -vv),
// replaces the global level and the category levels.
// Throws std::runtime_error if the output cannot be opened.
void init(const LogConfig& cfg, std::optional<LogLevel> cli_level = std::nullopt);

spdlog::logger& activity();
spdlog::logger& config();

void set_level(Category cat, LogLevel level);
LogLevel level(Category cat);

// "level" (both categories) or "category=level". Returns an
// error message, empty on success.
std::string apply_level_spec(std::string_view spec);

// Reopens the log file (after an external rotation). False if the output is stderr.
// Throws std::runtime_error if the file cannot be reopened (the old one stays in use).
bool reopen();

// Current output: "stderr" or the file path.
std::string output();

spdlog::level::level_enum to_spdlog(LogLevel level);

// JSON format: one line per event {"ts","level","cat","msg"}.
std::unique_ptr<spdlog::formatter> make_json_formatter();
std::string json_escape(std::string_view text);

}  // namespace tlsrelay::logging
