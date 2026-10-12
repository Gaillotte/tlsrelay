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
//   index.tsv                            inventaire : série, rôle, état, fin de validité, sujet,
//                                        date et motif de révocation
//   issued/<série>.pem                   certificats émis
//   crl.pem, crlnumber                   dernières CRL publiées (AC Serveurs, AC Clients) et leur numéro
//   audit.log                            journal d'audit chaîné (pki/audit.hpp)

#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/pki/request.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
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
    std::string status;  // valide, remplacé, révoqué
    std::string not_after;
    std::string subject;
    std::string revoked_at;  // date de révocation (vide sinon)
    std::string reason;      // motif de révocation (RFC 5280), vide sinon
};

std::vector<IndexEntry> list_issued(const std::filesystem::path& dir);

// Motifs de révocation retenus (RFC 5280 §5.3.1).
enum class RevocationReason { unspecified, key_compromise, superseded, cessation_of_operation };
std::string_view to_string(RevocationReason reason);  // unspecified, keyCompromise, superseded, cessationOfOperation
std::optional<RevocationReason> parse_revocation_reason(std::string_view text);

// Révoque un certificat émis (série en hexadécimal, casse indifférente) :
// l'inventaire le marque révoqué ; il figurera dans la prochaine CRL
// (publish_crl). Refuse une série inconnue ou déjà révoquée. Lève
// std::runtime_error.
IndexEntry revoke_certificate(const std::filesystem::path& dir, const std::string& serial, RevocationReason reason);

struct CrlInfo {
    std::string pem;  // CRL de l'AC Serveurs puis de l'AC Clients
    std::uint64_t number = 0;
    std::string next_update;
    std::size_t revoked = 0;  // certificats révoqués listés (les deux CRL)
};

// Publie les CRL des deux AC intermédiaires (validité days jours, jamais
// au-delà de la fin de validité de l'AC), les écrit dans <ac>/crl.pem et les
// retourne. Les certificats révoqués arrivés à expiration y restent listés.
// Lève std::runtime_error (phrase de passe incorrecte, etc.).
CrlInfo publish_crl(const std::filesystem::path& dir, const std::string& passphrase, int days = 30);

// Vue d'ensemble d'une AC (éditeur tlsrelay-admin).
struct CaCertificate {
    std::string subject;
    std::string not_after;
    std::string fingerprint;  // SHA-256, hexadécimal par paires séparées par « : »
};

struct AuthorityInfo {
    CaCertificate root;
    CaCertificate servers;
    CaCertificate clients;
    std::size_t issued = 0;
    std::size_t valid = 0;    // état valide et non expiré
    std::size_t revoked = 0;
    std::uint64_t crl_number = 0;  // 0 : aucune CRL publiée
    std::string crl_next_update;   // vide si aucune CRL
};

// Lit les certificats et l'inventaire d'un répertoire d'AC. Lève
// std::runtime_error si ce n'est pas un répertoire d'AC lisible.
AuthorityInfo describe_authority(const std::filesystem::path& dir);

// Vrai si la date de l'inventaire (« 2027-01-31 12:00:00Z ») est passée.
bool is_past(const std::string& date);

// Changement de racine (SPEC §7.5) entre l'AC en service (old_dir) et la
// nouvelle (new_dir). Écrit dans out :
//   serveur/trust-roots.pem, serveur/trust-issuer.pem   étapes 1 et 2, instances serveur
//   client/trust-roots.pem, client/trust-issuer.pem     étapes 1 et 2, instances client
//   crl.pem                                             CRL des deux AC (si publiées)
//   LISEZMOI.txt                                        les trois étapes, commandes comprises
// Les deux racines doivent différer. L'opération est tracée dans le journal
// d'audit des deux AC. Lève std::runtime_error.
void write_root_transition(const std::filesystem::path& old_dir, const std::filesystem::path& new_dir,
                           const std::filesystem::path& out);

}  // namespace tlsrelay::pki
