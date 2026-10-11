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
    std::vector<tls::X509Ptr> trust_issuers;  // AC qui peuvent avoir émis le certificat du pair
                                              // (une par racine ; deux pendant un changement de racine)

    // Vrai si ca est l'une des AC attendues chez le pair.
    bool is_expected_issuer(const X509* ca) const;
    // Vrai si les deux générations ont au moins une racine de confiance commune.
    bool shares_root_with(const Generation& other) const;
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

// Garde-fou de rotation (SPEC §7.3) : retourne la raison du refus, ou
// std::nullopt si next peut remplacer current sans couper les pairs :
// - au moins une racine de confiance commune ;
// - le nouveau certificat se rattache à une racine de la génération courante.
std::optional<std::string> rotation_guard(const Generation& current, const Generation& next, const Requirements& req);

// Contrôle d'une génération candidate avant activation : contrôles de
// load_generation, plus le garde-fou de rotation.
LoadResult check_candidate(const std::filesystem::path& pki_root, const std::string& name, const Requirements& req);

// Active une génération : remplace <pki_root>/current par renommage atomique.
// Lève std::filesystem::filesystem_error en cas d'échec.
void activate(const std::filesystem::path& pki_root, const std::string& name);

// Exigences d'une configuration, ou std::nullopt si aucun port TLS n'est configuré.
std::optional<Requirements> requirements_for(const Config& config);

}  // namespace tlsrelay::pki
