#pragma once

// Listes de révocation appliquées par le service (SPEC §7.7) :
// <pki_root>/crl.pem contient les CRL publiées par la mini-AC (ca crl), une
// par AC intermédiaire. Seules comptent celles des AC attendues chez le pair
// (trust-issuer.pem) ; leur signature est vérifiée avec la clé de l'AC.

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
    // Vrai si le certificat figure dans une CRL de son émetteur.
    bool is_revoked(const X509* cert) const;
    // Certificats révoqués listés par les CRL retenues.
    std::size_t size() const;
    // Plus proche date de prochaine mise à jour des CRL retenues (UTC).
    const std::string& next_update() const { return next_update_; }
    // Séries révoquées, « AC/série » (journal des changements au rechargement).
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
    std::shared_ptr<const RevocationList> list;  // présent seulement si errors est vide
    std::vector<Issue> errors;
    std::vector<Issue> warnings;
};

// Lit et contrôle le fichier de CRL pour une génération : CRL lisibles,
// signées par une AC attendue chez le pair (ou par l'AC de l'instance, pour
// signaler un certificat de l'instance révoqué). Une CRL dont la date de
// prochaine mise à jour est passée reste appliquée, avec un avertissement.
RevocationResult load_revocations(const std::filesystem::path& file, const Generation& generation);

}  // namespace tlsrelay::pki
