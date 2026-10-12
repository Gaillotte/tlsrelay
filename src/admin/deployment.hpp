#pragma once

// Paquet de déploiement d'une instance (export de tlsrelay-admin) : un
// répertoire à copier sur la machine de l'instance, avec la configuration,
// la liste blanche, le kit PKI et les CRL éventuels, un script d'installation
// et ses instructions.
//
//   <sortie>/<instance>/
//     <instance>.yaml          configuration
//     whitelist.yaml           liste blanche (serveur)
//     kit/                     kit produit par « ca sign » (facultatif)
//     crl.pem                  CRL publiées par l'AC (facultatif)
//     install.sh | install.ps1 installation (Linux | Windows)
//     LISEZMOI.txt             étapes, dans l'ordre

#include "tlsrelay/config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::admin {

enum class TargetPlatform { linux_host, windows_host };

struct ExportRequest {
    std::filesystem::path out_dir;  // le paquet est créé dans out_dir/<instance>
    TargetPlatform platform = TargetPlatform::linux_host;
    Config config;                 // configuration valide
    std::string config_text;       // texte enregistré (to_yaml)
    std::optional<std::string> whitelist_text;  // serveur
    std::optional<std::filesystem::path> kit_dir;
    std::optional<std::filesystem::path> crl_file;
};

// Points à signaler avant l'export (chemins relatifs, PKI sans kit, etc.).
std::vector<std::string> export_warnings(const ExportRequest& request);

// Crée le paquet ; retourne son répertoire. Refuse un répertoire de paquet
// existant et non vide, un kit incomplet ou un fichier de CRL illisible.
// Lève std::runtime_error.
std::filesystem::path export_package(const ExportRequest& request);

// Emplacement de la configuration d'une instance sur la machine cible
// (celui qu'utilisent « --instance » et « service install »).
std::string default_config_path(TargetPlatform platform, const std::string& instance);

}  // namespace tlsrelay::admin
