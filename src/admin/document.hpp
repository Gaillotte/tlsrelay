#pragma once

// Fichiers édités par tlsrelay-admin : lecture, écriture atomique avec copie
// de sauvegarde, chemins. Sans dépendance à Qt (testé seul).

#include <QString>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::admin {

// En-tête des fichiers écrits par l'éditeur (commentaire YAML).
inline constexpr const char* kWrittenBy =
    "Écrit par tlsrelay-admin. Les commentaires ne sont pas conservés à l'enregistrement.";

// Contenu d'un fichier, ou std::nullopt s'il est absent ou illisible.
std::optional<std::string> read_text(const std::filesystem::path& path);

// Écrit un fichier par renommage atomique. Si le fichier existait avec un
// autre contenu, il est d'abord copié en <fichier>.bak. Lève std::runtime_error.
void write_with_backup(const std::filesystem::path& path, const std::string& content);

// Chemin d'un fichier référencé par une configuration (liste blanche) : un
// chemin relatif est résolu depuis le répertoire de la configuration.
std::filesystem::path resolve_from(const std::filesystem::path& config_path, const std::string& file);

// Conversions sans perte (UTF-8) entre QString et chemins.
std::filesystem::path to_path(const QString& text);
QString to_qstring(const std::filesystem::path& path);

// Modification proposée à l'enregistrement : un fichier, son contenu actuel
// (absent : création) et le nouveau contenu.
struct FileChange {
    std::filesystem::path path;
    std::optional<std::string> before;
    std::string after;

    bool changed() const { return !before || *before != after; }
};

}  // namespace tlsrelay::admin
