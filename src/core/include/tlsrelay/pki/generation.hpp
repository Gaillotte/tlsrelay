#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"
#include "tlsrelay/units.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Génération PKI (SPEC §7.2) : contenu d'un répertoire <pki_root>/vN désigné
// par le fichier <pki_root>/current.
namespace tlsrelay::pki {

enum class Role { server, client };

// Ce dont l'instance a besoin selon son mode et ses ports.
struct Requirements {
    Role role = Role::server;
    bool identity = false;  // key.pem, cert.pem, chain.pem : présentés au pair
    bool trust = false;     // trust-roots.pem, trust-issuer.pem : vérification du pair
    Duration expiry_warning = std::chrono::days(30);
};

struct Generation {
    std::string name;  // "v1"
    std::filesystem::path dir;
    tls::EvpPkeyPtr key;
    tls::X509Ptr cert;
    std::vector<tls::X509Ptr> chain;        // AC intermédiaire(s) qui a émis cert
    std::vector<tls::X509Ptr> trust_roots;  // racines de confiance
    tls::X509Ptr trust_issuer;              // AC qui doit avoir émis le certificat du pair
};

struct LoadResult {
    std::shared_ptr<const Generation> generation;  // présent seulement si errors est vide
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

// Lit <pki_root>/current et charge le répertoire qu'il désigne.
LoadResult load_current_generation(const std::filesystem::path& pki_root, const Requirements& req);

// Charge et valide un répertoire de génération (contrôles de SPEC §7.3, hors
// garde-fou de rotation qui relève de la phase 4).
LoadResult load_generation(const std::filesystem::path& dir, const Requirements& req);

// Exigences d'une configuration, ou std::nullopt si aucun port TLS n'est configuré.
std::optional<Requirements> requirements_for(const Config& config);

}  // namespace tlsrelay::pki
