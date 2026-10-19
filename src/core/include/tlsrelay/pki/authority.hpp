#pragma once

// Command-line mini-CA (SPEC §7.1 and §7.6), for an administration
// workstation: root and two intermediate CAs (Servers, Clients),
// encrypted keys (PKCS#8 AES-256-CBC, scrypt derivation), signing of
// requests according to the CA policy and inventory of issued certificates.
//
// CA directory:
//   root.key.pem, root.cert.pem          root (P-384, 15 years)
//   servers.key.pem, servers.cert.pem    Servers CA (P-384, 5 years, pathlen 0, serverAuth)
//   clients.key.pem, clients.cert.pem    Clients CA (P-384, 5 years, pathlen 0, clientAuth)
//   index.tsv                            inventory: serial, role, status, not after, subject,
//                                        revocation date and reason
//   issued/<serial>.pem                  issued certificates
//   crl.pem, crlnumber                   latest published CRLs (Servers CA, Clients CA) and their number
//   audit.log                            hash-chained audit log (pki/audit.hpp)

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

// Creates the CA in dir (empty or missing). Throws std::runtime_error.
void init_authority(const std::filesystem::path& dir, const std::string& passphrase, const AuthorityOptions& options);

struct SignRequest {
    Role role = Role::server;
    std::string csr_pem;
    SubjectAltNames sans;  // set by the CA; required for a server
    int days = 365;
    bool renew = false;  // allows an already assigned subject (renewal); the old one is marked replaced
};

struct IssuedCertificate {
    std::string serial;
    std::string subject;
    std::string not_after;
    std::vector<std::string> ignored_extensions;  // extensions requested in the CSR, not carried over
    std::string cert_pem;
    std::string chain_pem;   // intermediate CA that signed
    std::string roots_pem;   // root
    std::string issuer_pem;  // CA expected from peers (the other intermediate)
};

// Checks a signing request without signing it: readable, valid signature
// (proof of possession), ECDSA P-256 key, subject with CN. Throws
// std::runtime_error on refusal.
struct RequestInfo {
    std::string subject;
    std::vector<std::string> requested_extensions;
};
RequestInfo inspect_request(const std::string& csr_pem);

// Signs a request. Refuses a key other than P-256, a request with an invalid
// signature, a subject without CN or already assigned (unless renew), a
// server without SAN, a wrong passphrase. Throws std::runtime_error.
IssuedCertificate sign_request(const std::filesystem::path& dir, const std::string& passphrase, const SignRequest& request);

// Writes the kit to install with "pki install --from": cert.pem, chain.pem,
// trust-roots.pem, trust-issuer.pem.
void write_bundle(const std::filesystem::path& out, const IssuedCertificate& issued);

struct IndexEntry {
    std::string serial;
    std::string role;    // server, client
    std::string status;  // valid, replaced, revoked
    std::string not_after;
    std::string subject;
    std::string revoked_at;  // revocation date (empty otherwise)
    std::string reason;      // revocation reason (RFC 5280), empty otherwise
};

std::vector<IndexEntry> list_issued(const std::filesystem::path& dir);

// Supported revocation reasons (RFC 5280 §5.3.1).
enum class RevocationReason { unspecified, key_compromise, superseded, cessation_of_operation };
std::string_view to_string(RevocationReason reason);  // unspecified, keyCompromise, superseded, cessationOfOperation
std::optional<RevocationReason> parse_revocation_reason(std::string_view text);

// Revokes an issued certificate (serial in hexadecimal, case-insensitive):
// the inventory marks it revoked; it will appear in the next CRL
// (publish_crl). Refuses an unknown or already revoked serial. Throws
// std::runtime_error.
IndexEntry revoke_certificate(const std::filesystem::path& dir, const std::string& serial, RevocationReason reason);

struct CrlInfo {
    std::string pem;  // CRL of the Servers CA, then of the Clients CA
    std::uint64_t number = 0;
    std::string next_update;
    std::size_t revoked = 0;  // revoked certificates listed (both CRLs)
};

// Publishes the CRLs of both intermediate CAs (valid for days days, never
// beyond the CA's expiry), writes them to <ca>/crl.pem and returns them.
// Revoked certificates that have expired stay listed.
// Throws std::runtime_error (wrong passphrase, etc.).
CrlInfo publish_crl(const std::filesystem::path& dir, const std::string& passphrase, int days = 30);

// Overview of a CA (tlsrelay-admin editor).
struct CaCertificate {
    std::string subject;
    std::string not_after;
    std::string fingerprint;  // SHA-256, hexadecimal pairs separated by ":"
};

struct AuthorityInfo {
    CaCertificate root;
    CaCertificate servers;
    CaCertificate clients;
    std::size_t issued = 0;
    std::size_t valid = 0;    // status valid and not expired
    std::size_t revoked = 0;
    std::uint64_t crl_number = 0;  // 0: no CRL published
    std::string crl_next_update;   // empty if no CRL
};

// Reads the certificates and inventory of a CA directory. Throws
// std::runtime_error if it is not a readable CA directory.
AuthorityInfo describe_authority(const std::filesystem::path& dir);

// True if the inventory date ("2027-01-31 12:00:00Z") is in the past.
bool is_past(const std::string& date);

// Root change (SPEC §7.5) between the CA in service (old_dir) and the
// new one (new_dir). Writes to out:
//   server/trust-roots.pem, server/trust-issuer.pem     steps 1 and 2, server instances
//   client/trust-roots.pem, client/trust-issuer.pem     steps 1 and 2, client instances
//   crl.pem                                             CRLs of both CAs (if published)
//   README.txt                                          the three steps, commands included
// The two roots must differ. The operation is recorded in the audit log
// of both CAs. Throws std::runtime_error.
void write_root_transition(const std::filesystem::path& old_dir, const std::filesystem::path& new_dir,
                           const std::filesystem::path& out);

}  // namespace tlsrelay::pki
