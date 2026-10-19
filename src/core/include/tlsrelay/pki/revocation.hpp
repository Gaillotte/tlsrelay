#pragma once

// Revocation lists applied by the service (SPEC §7.7):
// <pki_root>/crl.pem contains the CRLs published by the mini-CA (ca crl), one
// per intermediate CA. Only those of the CAs expected from the peer count
// (trust-issuer.pem); their signature is verified with the CA's key.

#include "tlsrelay/config.hpp"
#include "tlsrelay/pki/generation.hpp"

#include <openssl/x509.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace tlsrelay::pki {

inline constexpr const char* kCrlFile = "crl.pem";

class RevocationList {
public:
    // True if the certificate appears in a CRL of its issuer.
    bool is_revoked(const X509* cert) const;
    // Revoked certificates listed by the retained CRLs.
    std::size_t size() const;
    // Earliest next-update date of the retained CRLs (UTC).
    const std::string& next_update() const { return next_update_; }
    // Revoked serials, "CA/serial" (change log on reload).
    std::vector<std::string> entries() const;

private:
    friend struct RevocationLoader;
    struct CrlDeleter {
        void operator()(X509_CRL* crl) const { X509_CRL_free(crl); }
    };
    std::vector<std::unique_ptr<X509_CRL, CrlDeleter>> crls_;
    std::string next_update_;
};

struct RevocationResult {
    std::shared_ptr<const RevocationList> list;  // present only if errors is empty
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

// Reads and checks the CRL file for a generation: readable CRLs,
// signed by a CA expected from the peer (or by the instance's CA, to
// report a revoked instance certificate). A CRL whose next-update date
// has passed is still applied, with a warning.
RevocationResult load_revocations(const std::filesystem::path& file, const Generation& generation);

}  // namespace tlsrelay::pki
