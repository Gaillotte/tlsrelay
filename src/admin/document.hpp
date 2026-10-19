#pragma once

// Files edited by tlsrelay-admin: reading, atomic writing with a backup
// copy, paths. No dependency on Qt (tested alone).

#include <QString>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::admin {

// Header of the files written by the editor (YAML comment).
inline constexpr const char* kWrittenBy =
    "Written by tlsrelay-admin. Comments are not kept when saving.";

// Content of a file, or std::nullopt if it is missing or unreadable.
std::optional<std::string> read_text(const std::filesystem::path& path);

// Writes a file by atomic rename. If the file existed with different
// content, it is first copied to <file>.bak. Throws std::runtime_error.
void write_with_backup(const std::filesystem::path& path, const std::string& content);

// Path of a file referenced by a configuration (whitelist): a relative
// path is resolved from the configuration's directory.
std::filesystem::path resolve_from(const std::filesystem::path& config_path, const std::string& file);

// Lossless conversions (UTF-8) between QString and paths.
std::filesystem::path to_path(const QString& text);
QString to_qstring(const std::filesystem::path& path);

// Change proposed when saving: a file, its current content
// (missing: creation) and the new content.
struct FileChange {
    std::filesystem::path path;
    std::optional<std::string> before;
    std::string after;

    bool changed() const { return !before || *before != after; }
};

}  // namespace tlsrelay::admin
