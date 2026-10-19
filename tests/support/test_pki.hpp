#pragma once

// Test PKI factory (PLAN §5): hierarchy root -> Servers CA / Clients CA
// -> certificates, generated on the fly, with "trapped" variants.

#include "tlsrelay/tls/openssl_ptr.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace testpki {

using tlsrelay::tls::EvpPkeyPtr;
using tlsrelay::tls::X509Ptr;

enum class Usage { none, server, client };

struct CertOptions {
    std::string common_name{};
    bool ca = false;
    Usage usage = Usage::none;
    std::vector<std::string> dns{};
    std::vector<std::string> ips{};
    long not_before_offset = -3600;           // seconds relative to now
    long not_after_offset = 365L * 24 * 3600;
    const char* curve = "P-256";
};

struct Issued {
    EvpPkeyPtr key;
    X509Ptr cert;
};

// Self-signed certificate (root) or issued by issuer.
Issued make_certificate(const CertOptions& options, const Issued* issuer = nullptr);

std::string pem(const X509* cert);
std::string pem(const EVP_PKEY* key);
std::string encrypted_pem(const EVP_PKEY* key, const char* password);

// Standard project hierarchy (PLAN §2): root, Servers CA, Clients CA,
// a server certificate (relay.test, 127.0.0.1) and a client certificate.
struct Hierarchy {
    Issued root;
    Issued servers_ca;
    Issued clients_ca;
    Issued server;
    Issued client;

    static Hierarchy create(const std::string& label = "Test");
};

// Contents of a generation directory (SPEC §7.2); an empty field is not written.
struct GenerationFiles {
    std::optional<std::string> key;
    std::optional<std::string> cert;
    std::optional<std::string> chain;
    std::optional<std::string> trust_roots;
    std::optional<std::string> trust_issuer;
};

// Writes <pki_root>/<name>/... and, if activate, <pki_root>/current.
void write_generation(const std::filesystem::path& pki_root, const std::string& name, const GenerationFiles& files,
                      bool activate = true);

// Ready-to-use directories for a server or client tlsrelay.
GenerationFiles server_files(const Hierarchy& h);
GenerationFiles client_files(const Hierarchy& h);

// Temporary directory removed on destruction.
class TempDir {
public:
    TempDir();
    ~TempDir();
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const std::filesystem::path& path() const { return path_; }
    std::filesystem::path operator/(const std::string& sub) const { return path_ / sub; }

private:
    std::filesystem::path path_;
};

}  // namespace testpki
