#pragma once

// Mini-AC en ligne de commande (SPEC §7.1 et §7.6), pour un poste
// d'administration : racine et deux AC intermédiaires (Serveurs, Clients),
// clés chiffrées (PKCS#8 AES-256-CBC, dérivation scrypt), signature des
// demandes selon la politique de l'AC et inventaire des certificats émis.
//
// Répertoire de l'AC :
//   root.key.pem, root.cert.pem          racine (P-384, 15 ans)
//   servers.key.pem, servers.cert.pem    AC Serveurs (P-384, 5 ans, pathlen 0, serverAuth)
//   clients.key.pem, clients.cert.pem    AC Clients (P-384, 5 ans, pathlen 0, clientAuth)
//   index.tsv                            inventaire : série, rôle, état, fin de validité, sujet
//   issued/<série>.pem                   certificats émis

#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/pki/request.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace tlsrelay::pki {

inline constexpr std::size_t kMinPassphrase = 12;

struct AuthorityOptions {
    std::string organization = "tlsrelay";
    int root_days = 15 * 365 + 4;
    int ca_days = 5 * 365 + 1;
};

// Crée l'AC dans dir (vide ou absent). Lève std::runtime_error.
void init_authority(const std::filesystem::path& dir, const std::string& passphrase, const AuthorityOptions& options);

struct SignRequest {
    Role role = Role::server;
    std::string csr_pem;
    SubjectAltNames sans;  // fixés par l'AC ; obligatoires pour un serveur
    int days = 365;
    bool renew = false;  // autorise un sujet déjà attribué (renouvellement) ; l'ancien est marqué remplacé
};

struct IssuedCertificate {
    std::string serial;
    std::string subject;
    std::string not_after;
    std::vector<std::string> ignored_extensions;  // extensions demandées dans la CSR, non reprises
    std::string cert_pem;
    std::string chain_pem;   // AC intermédiaire qui a signé
    std::string roots_pem;   // racine
    std::string issuer_pem;  // AC attendue chez les pairs (l'autre intermédiaire)
};

// Contrôle d'une demande de signature, sans la signer : lisible, signature
// valide (preuve de possession), clé ECDSA P-256, sujet avec CN. Lève
// std::runtime_error en cas de refus.
struct RequestInfo {
    std::string subject;
    std::vector<std::string> requested_extensions;
};
RequestInfo inspect_request(const std::string& csr_pem);

// Signe une demande. Refuse une clé autre que P-256, une demande dont la
// signature est invalide, un sujet sans CN ou déjà attribué (sauf renew), un
// serveur sans SAN, une phrase de passe incorrecte. Lève std::runtime_error.
IssuedCertificate sign_request(const std::filesystem::path& dir, const std::string& passphrase, const SignRequest& request);

// Écrit le kit à installer avec « pki install --from » : cert.pem, chain.pem,
// trust-roots.pem, trust-issuer.pem.
void write_bundle(const std::filesystem::path& out, const IssuedCertificate& issued);

struct IndexEntry {
    std::string serial;
    std::string role;    // server, client
    std::string status;  // valide, remplacé
    std::string not_after;
    std::string subject;
};

std::vector<IndexEntry> list_issued(const std::filesystem::path& dir);

}  // namespace tlsrelay::pki
