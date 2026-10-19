#pragma once

#include "tlsrelay/config.hpp"
#include "tlsrelay/tls/openssl_ptr.hpp"
#include "tlsrelay/units.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// PKI generation (SPEC §7.2): contents of a <pki_root>/vN directory designated
// by the <pki_root>/current file.
namespace tlsrelay::pki {

enum class Role { server, client };

// What the instance needs according to its mode and ports.
struct Requirements {
    Role role = Role::server;
    bool identity = false;  // key.pem, cert.pem, chain.pem: presented to the peer
    bool trust = false;     // trust-roots.pem, trust-issuer.pem: peer verification
    Duration expiry_warning = std::chrono::days(30);
};

struct Generation {
    std::string name;  // "v1"
    std::filesystem::path dir;
    tls::EvpPkeyPtr key;
    tls::X509Ptr cert;
    std::vector<tls::X509Ptr> chain;        // intermediate CA(s) that issued cert
    std::vector<tls::X509Ptr> trust_roots;  // trusted roots
    std::vector<tls::X509Ptr> trust_issuers;  // CAs that may have issued the peer's certificate
                                              // (one per root; two during a root change)

    // True if ca is one of the CAs expected from the peer.
    bool is_expected_issuer(const X509* ca) const;
    // True if both generations share at least one trusted root.
    bool shares_root_with(const Generation& other) const;
};

struct LoadResult {
    std::shared_ptr<const Generation> generation;  // present only if errors is empty
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

// Reads <pki_root>/current and loads the directory it designates.
LoadResult load_current_generation(const std::filesystem::path& pki_root, const Requirements& req);

// Loads and validates a generation directory (checks of SPEC §7.3, except
// the rotation safeguard, which belongs to phase 4).
LoadResult load_generation(const std::filesystem::path& dir, const Requirements& req);

// Rotation safeguard (SPEC §7.3): returns the reason for refusal, or
// std::nullopt if next can replace current without cutting off peers:
// - at least one common trusted root;
// - the new certificate chains to a root of the current generation.
std::optional<std::string> rotation_guard(const Generation& current, const Generation& next, const Requirements& req);

// Checks a candidate generation before activation: the checks of
// load_generation, plus the rotation safeguard.
LoadResult check_candidate(const std::filesystem::path& pki_root, const std::string& name, const Requirements& req);

// Activates a generation: replaces <pki_root>/current by atomic rename.
// Throws std::filesystem::filesystem_error on failure.
void activate(const std::filesystem::path& pki_root, const std::string& name);

// Requirements of a configuration, or std::nullopt if no TLS port is configured.
std::optional<Requirements> requirements_for(const Config& config);

}  // namespace tlsrelay::pki
