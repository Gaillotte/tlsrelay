#pragma once

// Instance side (SPEC §7.6): the key pair is generated on the tlsrelay machine
// and never leaves it; only the signing request (CSR) does.
//
//   pki gen-csr:  new generation vN with key.pem and request.csr
//   pki install:  completes vN with the signed certificate and the trust files

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
    // OpenSSL form: "DNS:a,IP:1.2.3.4".
    std::string to_openssl() const;
};

// Parses "dns:name", "ip:address", or a bare value (IP address or name).
// Returns std::nullopt and fills error if a value is invalid.
std::optional<SubjectAltNames> parse_sans(const std::vector<std::string>& items, std::string& error);

// Name of the next generation: v<highest number + 1> (v1 if none).
std::string next_generation_name(const std::filesystem::path& pki_root);

// Latest generation with a pending request (key.pem and request.csr, without cert.pem).
std::optional<std::string> pending_generation(const std::filesystem::path& pki_root);

struct CsrResult {
    std::string generation;
    std::filesystem::path csr;
    std::string subject;
};

// Creates the next generation: ECDSA P-256 key (key.pem, readable by the owner
// only) and signed request request.csr. The SANs in it are for information
// only: the CA sets those of the certificate. Throws std::runtime_error.
CsrResult generate_csr(const std::filesystem::path& pki_root, const std::string& subject,
                       const SubjectAltNames& sans);

// Files to install. A missing trust file is taken from the current
// generation; from designates a directory produced by "ca sign".
struct InstallFiles {
    std::optional<std::filesystem::path> from;
    std::optional<std::filesystem::path> cert;
    std::optional<std::filesystem::path> chain;
    std::optional<std::filesystem::path> roots;
    std::optional<std::filesystem::path> issuer;
};

struct InstallResult {
    std::string generation;
    LoadResult check;  // checks of check_candidate (without activation)
};

// Completes the given generation (by default: the pending request; for
// an instance without identity, a new generation). Activates nothing.
// Throws std::runtime_error if files are missing or cannot be copied.
InstallResult install(const std::filesystem::path& pki_root, std::optional<std::string> generation,
                      const InstallFiles& files, const Requirements& req);

}  // namespace tlsrelay::pki
