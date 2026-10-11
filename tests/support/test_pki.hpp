#pragma once

// Fabrique de PKI de test (PLAN §5) : hiérarchie racine -> AC Serveurs / AC
// Clients -> certificats, générée à la volée, avec des variantes « piégées ».

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
    long not_before_offset = -3600;           // secondes par rapport à maintenant
    long not_after_offset = 365L * 24 * 3600;
    const char* curve = "P-256";
};

struct Issued {
    EvpPkeyPtr key;
    X509Ptr cert;
};

// Certificat auto-signé (racine) ou émis par issuer.
Issued make_certificate(const CertOptions& options, const Issued* issuer = nullptr);

std::string pem(const X509* cert);
std::string pem(const EVP_PKEY* key);
std::string encrypted_pem(const EVP_PKEY* key, const char* password);

// Hiérarchie standard du projet (PLAN §2) : racine, AC Serveurs, AC Clients,
// un certificat serveur (relay.test, 127.0.0.1) et un certificat client.
struct Hierarchy {
    Issued root;
    Issued servers_ca;
    Issued clients_ca;
    Issued server;
    Issued client;

    static Hierarchy create(const std::string& label = "Test");
};

// Contenu d'un répertoire de génération (SPEC §7.2) ; un champ vide n'est pas écrit.
struct GenerationFiles {
    std::optional<std::string> key;
    std::optional<std::string> cert;
    std::optional<std::string> chain;
    std::optional<std::string> trust_roots;
    std::optional<std::string> trust_issuer;
};

// Écrit <pki_root>/<name>/... et, si activate, <pki_root>/current.
void write_generation(const std::filesystem::path& pki_root, const std::string& name, const GenerationFiles& files,
                      bool activate = true);

// Répertoires prêts à l'emploi pour un tlsrelay serveur ou client.
GenerationFiles server_files(const Hierarchy& h);
GenerationFiles client_files(const Hierarchy& h);

// Répertoire temporaire supprimé à la destruction.
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
