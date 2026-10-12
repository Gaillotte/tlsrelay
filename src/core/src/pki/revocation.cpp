#include "tlsrelay/pki/revocation.hpp"

#include "files.hpp"

#include <openssl/err.h>
#include <openssl/x509v3.h>

namespace tlsrelay::pki {

namespace {

std::string serial_text(const ASN1_INTEGER* serial) {
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* hex = bn ? BN_bn2hex(bn) : nullptr;
    std::string out = hex ? hex : "?";
    OPENSSL_free(hex);
    BN_free(bn);
    return out;
}

}  // namespace

bool RevocationList::is_revoked(const X509* cert) const {
    if (!cert) return false;
    for (const auto& crl : crls_) {
        if (X509_NAME_cmp(X509_CRL_get_issuer(crl.get()), X509_get_issuer_name(cert)) != 0) continue;
        X509_REVOKED* entry = nullptr;
        if (X509_CRL_get0_by_serial(crl.get(), &entry, const_cast<ASN1_INTEGER*>(X509_get0_serialNumber(cert))) == 1) {
            return true;
        }
    }
    return false;
}

std::size_t RevocationList::size() const {
    std::size_t count = 0;
    for (const auto& crl : crls_) {
        const int n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl.get()));
        if (n > 0) count += static_cast<std::size_t>(n);
    }
    return count;
}

std::vector<std::string> RevocationList::entries() const {
    std::vector<std::string> out;
    for (const auto& crl : crls_) {
        const auto issuer = tls::name_to_string(X509_CRL_get_issuer(crl.get()));
        STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(crl.get());
        for (int i = 0; i < sk_X509_REVOKED_num(revoked); ++i) {
            out.push_back(issuer + "/" + serial_text(X509_REVOKED_get0_serialNumber(sk_X509_REVOKED_value(revoked, i))));
        }
    }
    return out;
}

struct RevocationLoader {
    static RevocationResult load(const std::filesystem::path& file, const Generation& gen) {
        RevocationResult result;
        const auto where = file.string();
        std::string pem;
        try {
            pem = detail::read_file(file);
        } catch (const std::exception&) {
            result.errors.push_back({where, "fichier illisible"});
            return result;
        }
        auto list = std::make_shared<RevocationList>();
        tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
        std::vector<std::unique_ptr<X509_CRL, RevocationList::CrlDeleter>> crls;
        while (X509_CRL* crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) crls.emplace_back(crl);
        ERR_clear_error();
        if (crls.empty()) {
            result.errors.push_back({where, "aucune CRL PEM trouvée"});
            return result;
        }

        // AC dont la CRL compte : celles attendues chez le pair. L'AC de
        // l'instance (chain.pem) sert seulement à signaler sa propre révocation.
        auto signed_by = [](const X509_CRL* crl, const std::vector<tls::X509Ptr>& cas) -> const X509* {
            for (const auto& ca : cas) {
                if (X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(ca.get())) != 0) continue;
                if (X509_CRL_verify(const_cast<X509_CRL*>(crl), X509_get0_pubkey(ca.get())) == 1) return ca.get();
            }
            ERR_clear_error();
            return nullptr;
        };
        auto names_issuer = [](const X509_CRL* crl, const std::vector<tls::X509Ptr>& cas) {
            for (const auto& ca : cas) {
                if (X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(ca.get())) == 0) return true;
            }
            return false;
        };

        std::vector<bool> covered(gen.trust_issuers.size(), false);
        for (auto& crl : crls) {
            const auto issuer = tls::name_to_string(X509_CRL_get_issuer(crl.get()));
            const X509* ca = signed_by(crl.get(), gen.trust_issuers);
            if (!ca) {
                if (names_issuer(crl.get(), gen.trust_issuers)) {
                    result.errors.push_back({where, "CRL de « " + issuer + " » : signature invalide"});
                    continue;
                }
                // CRL d'une autre AC (fichier commun aux deux rôles) : sert
                // seulement à signaler la révocation du certificat de l'instance.
                if (gen.cert && signed_by(crl.get(), gen.chain)) {
                    X509_REVOKED* entry = nullptr;
                    if (X509_CRL_get0_by_cert(crl.get(), &entry, gen.cert.get()) == 1) {
                        result.warnings.push_back({where, "le certificat de cette instance (" +
                                                              tls::subject_of(gen.cert.get()) +
                                                              ") est révoqué : le renouveler"});
                    }
                }
                continue;
            }
            for (std::size_t i = 0; i < gen.trust_issuers.size(); ++i) {
                if (gen.trust_issuers[i].get() == ca) covered[i] = true;
            }
            const ASN1_TIME* next = X509_CRL_get0_nextUpdate(crl.get());
            if (X509_cmp_current_time(X509_CRL_get0_lastUpdate(crl.get())) > 0) {
                result.warnings.push_back({where, "CRL de « " + issuer + " » datée dans le futur (horloge ?)"});
            }
            if (next && X509_cmp_current_time(next) < 0) {
                result.warnings.push_back({where, "CRL de « " + issuer + " » périmée depuis le " +
                                                      tls::time_to_string(next) +
                                                      " : toujours appliquée, à republier (ca crl)"});
            }
            const auto next_text = next ? tls::time_to_string(next) : std::string();
            if (!next_text.empty() && (list->next_update_.empty() || next_text < list->next_update_)) {
                list->next_update_ = next_text;
            }
            list->crls_.push_back(std::move(crl));
        }
        for (std::size_t i = 0; i < covered.size(); ++i) {
            if (!covered[i]) {
                result.warnings.push_back({where, "aucune CRL pour l'AC « " +
                                                      tls::subject_of(gen.trust_issuers[i].get()) +
                                                      " » : ses certificats ne sont pas contrôlés"});
            }
        }
        if (result.errors.empty()) result.list = std::move(list);
        return result;
    }
};

RevocationResult load_revocations(const std::filesystem::path& file, const Generation& generation) {
    return RevocationLoader::load(file, generation);
}

}  // namespace tlsrelay::pki
