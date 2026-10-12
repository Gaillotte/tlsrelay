#pragma once

// Journal d'audit de la mini-AC (<ac>/audit.log) : une ligne par opération
// (création, signature, révocation, publication de CRL), chaînée par SHA-256
// pour qu'une ligne modifiée, supprimée ou insérée soit détectée.
//
// Format d'une ligne, champs séparés par des tabulations :
//   date (UTC)  opérateur  opération  détails  empreinte
// empreinte = SHA-256 hexadécimal de « empreinte précédente \t ligne sans
// empreinte » ; la première ligne part de 64 zéros.

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::pki {

struct AuditEntry {
    std::string date;
    std::string operator_name;
    std::string operation;  // init, sign, revoke, crl
    std::string details;
};

// Ajoute une entrée. Tabulations et fins de ligne des champs sont remplacées
// par des espaces. Lève std::runtime_error si l'écriture échoue.
void append_audit(const std::filesystem::path& ca_dir, const std::string& operation, const std::string& details);

struct AuditLog {
    std::vector<AuditEntry> entries;  // lignes lues, jusqu'à la première rupture de chaîne exclue
    std::optional<std::size_t> broken_line;  // numéro (à partir de 1) de la première ligne non conforme
    std::string problem;                     // motif de la rupture
};

// Lit et vérifie le journal. Un journal absent est vide et valide (AC créée
// avant la livraison 1.1).
AuditLog read_audit(const std::filesystem::path& ca_dir);

// Compte du système qui exécute le programme (opérateur des entrées d'audit).
std::string current_operator();

}  // namespace tlsrelay::pki
