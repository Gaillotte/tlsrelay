#pragma once

// Côté instance (SPEC §7.6) : la bi-clé est générée sur la machine tlsrelay
// et ne la quitte jamais ; seule la demande de signature (CSR) en sort.
//
//   pki gen-csr  : nouvelle génération vN avec key.pem et request.csr
//   pki install  : complète vN avec le certificat signé et les fichiers de confiance

#include "tlsrelay/pki/generation.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::pki {

struct SubjectAltNames {
    std::vector<std::string> dns;
    std::vector<std::string> ip;

    bool empty() const { return dns.empty() && ip.empty(); }
    // Forme OpenSSL : « DNS:a,IP:1.2.3.4 ».
    std::string to_openssl() const;
};

// Analyse « dns:nom », « ip:adresse », ou une valeur seule (adresse IP ou nom).
// Retourne std::nullopt et remplit error si une valeur est invalide.
std::optional<SubjectAltNames> parse_sans(const std::vector<std::string>& items, std::string& error);

// Nom de la prochaine génération : v<plus grand numéro + 1> (v1 si aucune).
std::string next_generation_name(const std::filesystem::path& pki_root);

// Dernière génération avec une demande en attente (key.pem et request.csr, sans cert.pem).
std::optional<std::string> pending_generation(const std::filesystem::path& pki_root);

struct CsrResult {
    std::string generation;
    std::filesystem::path csr;
    std::string subject;
};

// Crée la génération suivante : clé ECDSA P-256 (key.pem, lisible par le seul
// propriétaire) et demande signée request.csr. Les SAN y sont indiqués à titre
// d'information : c'est l'AC qui fixe ceux du certificat. Lève std::runtime_error.
CsrResult generate_csr(const std::filesystem::path& pki_root, const std::string& subject,
                       const SubjectAltNames& sans);

// Fichiers à installer. Un fichier de confiance absent est repris de la
// génération courante ; from désigne un répertoire produit par « ca sign ».
struct InstallFiles {
    std::optional<std::filesystem::path> from;
    std::optional<std::filesystem::path> cert;
    std::optional<std::filesystem::path> chain;
    std::optional<std::filesystem::path> roots;
    std::optional<std::filesystem::path> issuer;
};

struct InstallResult {
    std::string generation;
    LoadResult check;  // contrôles de check_candidate (sans activation)
};

// Complète la génération donnée (par défaut : la demande en attente ; pour
// une instance sans identité, une nouvelle génération). N'active rien.
// Lève std::runtime_error si les fichiers manquent ou ne peuvent pas être copiés.
InstallResult install(const std::filesystem::path& pki_root, std::optional<std::string> generation,
                      const InstallFiles& files, const Requirements& req);

}  // namespace tlsrelay::pki
