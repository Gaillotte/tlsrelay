// Fabrique de PKI de test (PLAN §5), portable Windows et Linux : mini-AC,
// puis générations serveur et client par demande de signature, comme en
// production. --renew ajoute une génération (nouvelles clés) et l'active.

#include "pki.hpp"

#include "tlsrelay/pki/authority.hpp"
#include "tlsrelay/pki/request.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

namespace testkit {
namespace {

namespace fs = std::filesystem;
namespace pki = tlsrelay::pki;

// Réservée aux essais : écrite en clair dans le répertoire de la PKI de test.
constexpr const char* kPassphrase = "tlsrelay-testkit-pki";

std::string read(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream s;
    s << in.rdbuf();
    return s.str();
}

std::string provision(const fs::path& out, const fs::path& pki_root, pki::Role role, const std::string& subject,
                      const pki::SubjectAltNames& sans, bool renew) {
    const auto csr = pki::generate_csr(pki_root, subject, {});
    pki::SignRequest request;
    request.role = role;
    request.csr_pem = read(csr.csr);
    request.sans = sans;
    request.renew = renew;
    const auto issued = pki::sign_request(out / "ac", kPassphrase, request);
    const auto kit = out / "kits" / ((role == pki::Role::server ? "serveur-" : "client-") + csr.generation);
    pki::write_bundle(kit, issued);
    pki::InstallFiles files;
    files.from = kit;
    const auto result = pki::install(pki_root, csr.generation, files, {role, true, true});
    if (!result.check.generation) {
        std::string why;
        for (const auto& e : result.check.errors) why += "\n  " + e.path + " : " + e.message;
        throw std::runtime_error("génération " + csr.generation + " refusée :" + why);
    }
    pki::activate(pki_root, csr.generation);
    return csr.generation;
}

}  // namespace

int run_pki(const PkiOptions& o) {
    try {
        const fs::path out = o.out;
        const bool renew = fs::exists(out / "ac" / "root.cert.pem");
        if (!renew) {
            pki::AuthorityOptions authority;
            authority.organization = "tlsrelay-test";
            pki::init_authority(out / "ac", kPassphrase, authority);
            std::ofstream(out / "ac" / "LISEZMOI.txt")
                << "PKI DE TEST générée par tlsrelay-testkit. Phrase de passe de l'AC : " << kPassphrase
                << "\nNe jamais l'utiliser en production.\n";
        }
        std::string error;
        auto sans = pki::parse_sans(o.server_sans, error);
        if (!sans) throw std::runtime_error(error);
        const auto server = provision(out, out / "serveur", pki::Role::server, o.server_subject, *sans, renew);
        const auto client = provision(out, out / "client", pki::Role::client, o.client_subject, {}, renew);
        std::cout << (renew ? "nouvelle génération activée" : "PKI de test créée") << " dans " << out.string()
                  << " : serveur " << server << " (" << o.server_subject << "), client " << client << " ("
                  << o.client_subject << ")\n"
                  << "  credentials.pki_root : " << (out / "serveur").string() << " et " << (out / "client").string()
                  << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "erreur : " << e.what() << '\n';
        return 1;
    }
}

}  // namespace testkit
