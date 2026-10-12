#include "deployment.hpp"

#include "document.hpp"
#include "tlsrelay/pki/generation.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace tlsrelay::admin {
namespace {

namespace fs = std::filesystem;

constexpr const char* kKitFiles[] = {"cert.pem", "chain.pem", "trust-roots.pem", "trust-issuer.pem"};

bool is_absolute_for(TargetPlatform platform, const std::string& path) {
    if (platform == TargetPlatform::linux_host) return !path.empty() && path.front() == '/';
    // C:\..., C:/..., \\serveur\partage
    return (path.size() >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) || path.rfind("\\\\", 0) == 0;
}

// Chaîne entre apostrophes pour sh ('…' ; une apostrophe devient '\'').
std::string sh_quote(const std::string& text) {
    std::string out = "'";
    for (char c : text) out += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return out + "'";
}

// Chaîne entre apostrophes pour PowerShell (une apostrophe est doublée).
std::string ps_quote(const std::string& text) {
    std::string out = "'";
    for (char c : text) out += c == '\'' ? std::string("''") : std::string(1, c);
    return out + "'";
}

void write(const fs::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    out.close();
    if (!out) throw std::runtime_error("écriture impossible : " + path.string());
}

bool needs_identity_or_trust(const Config& config) { return pki::requirements_for(config).has_value(); }

std::string linux_script(const ExportRequest& r, const std::string& conf) {
    const auto& c = r.config;
    std::ostringstream s;
    s << "#!/bin/sh\n"
      << "# Installation de l'instance " << c.instance << " (paquet produit par tlsrelay-admin).\n"
      << "# À exécuter en root sur la machine de l'instance, depuis ce répertoire.\n"
      << "set -eu\n"
      << "here=$(cd \"$(dirname \"$0\")\" && pwd)\n"
      << "conf=" << sh_quote(conf) << "\n\n"
      << "install -d -m 0750 -o root -g tlsrelay /etc/tlsrelay\n"
      << "install -m 0640 -o root -g tlsrelay \"$here/" << c.instance << ".yaml\" \"$conf\"\n";
    if (r.whitelist_text && c.whitelist) {
        s << "install -D -m 0640 -o root -g tlsrelay \"$here/whitelist.yaml\" " << sh_quote(c.whitelist->file) << "\n";
    }
    if (c.credentials) {
        s << "install -d -m 0750 -o root -g tlsrelay " << sh_quote(c.credentials->pki_root) << "\n";
    }
    s << "tlsrelay check-config -c \"$conf\"\n";
    if (r.kit_dir) s << "tlsrelay pki install -c \"$conf\" --from \"$here/kit\"\n";
    if (r.crl_file) s << "tlsrelay pki crl -c \"$conf\" \"$here/crl.pem\"\n";
    s << "echo \"instance " << c.instance << " installée : suivre LISEZMOI.txt pour la suite\"\n";
    return s.str();
}

std::string windows_script(const ExportRequest& r) {
    const auto& c = r.config;
    std::ostringstream s;
    // UTF-8 avec BOM : lu correctement par Windows PowerShell 5.1.
    s << "\xEF\xBB\xBF"
      << "# Installation de l'instance " << c.instance << " (paquet produit par tlsrelay-admin).\n"
      << "# À exécuter dans un PowerShell administrateur, depuis ce répertoire.\n"
      << "#Requires -RunAsAdministrator\n"
      << "$ErrorActionPreference = 'Stop'\n"
      << "$tlsrelay = Join-Path $env:ProgramFiles 'tlsrelay\\bin\\tlsrelay.exe'\n"
      << "$dir = Join-Path $env:ProgramData 'tlsrelay'\n"
      << "$conf = Join-Path $dir " << ps_quote(c.instance + ".yaml") << "\n"
      << "function Run { & $tlsrelay @args; if ($LASTEXITCODE -ne 0) { throw \"tlsrelay $args : code $LASTEXITCODE\" } }\n\n"
      << "New-Item -ItemType Directory -Force $dir | Out-Null\n"
      << "Copy-Item (Join-Path $PSScriptRoot " << ps_quote(c.instance + ".yaml") << ") $conf -Force\n";
    if (r.whitelist_text && c.whitelist) {
        s << "$whitelist = " << ps_quote(c.whitelist->file) << "\n"
          << "New-Item -ItemType Directory -Force (Split-Path $whitelist) | Out-Null\n"
          << "Copy-Item (Join-Path $PSScriptRoot 'whitelist.yaml') $whitelist -Force\n";
    }
    if (c.credentials) {
        s << "New-Item -ItemType Directory -Force " << ps_quote(c.credentials->pki_root) << " | Out-Null\n";
    }
    s << "Run check-config -c $conf\n";
    if (r.kit_dir) s << "Run pki install -c $conf --from (Join-Path $PSScriptRoot 'kit')\n";
    if (r.crl_file) s << "Run pki crl -c $conf (Join-Path $PSScriptRoot 'crl.pem')\n";
    s << "Write-Host \"instance " << c.instance << " installée : suivre LISEZMOI.txt pour la suite\"\n";
    return s.str();
}

std::string readme(const ExportRequest& r, const std::string& conf) {
    const auto& c = r.config;
    const bool windows = r.platform == TargetPlatform::windows_host;
    // tlsrelay n'est pas dans le PATH sous Windows (INSTALLATION §3).
    const std::string tool = windows ? "& \"$env:ProgramFiles\\tlsrelay\\bin\\tlsrelay.exe\" " : "sudo tlsrelay ";
    std::ostringstream s;
    if (windows) s << "\xEF\xBB\xBF";
    s << "Paquet de déploiement de l'instance « " << c.instance << " » (mode " << to_string(c.mode) << ")\n"
      << "Produit par tlsrelay-admin. Voir aussi docs/INSTALLATION.md.\n\n"
      << "1. Installer le paquet tlsrelay sur la machine, puis copier ce répertoire.\n"
      << "2. Exécuter " << (windows ? "install.ps1 dans un PowerShell administrateur" : "sudo sh install.sh")
      << " : configuration copiée dans " << conf;
    if (r.whitelist_text && c.whitelist) s << ", liste blanche dans " << c.whitelist->file;
    s << ", contrôle de la configuration";
    if (r.kit_dir) s << ", installation du kit PKI";
    if (r.crl_file) s << ", installation des CRL";
    s << ".\n";
    int step = 3;
    if (needs_identity_or_trust(c) && !r.kit_dir) {
        s << step++ << ". PKI : créer la clé et la demande de signature sur cette machine :\n"
          << "     " << tool << "pki gen-csr -c " << conf << " --subject \"CN=...,O=...\""
          << (c.mode == Mode::server ? " --san <nom DNS ou IP>" : "") << "\n"
          << "   puis faire signer request.csr par l'AC (tlsrelay-admin ou tlsrelay ca sign) et installer le kit :\n"
          << "     " << tool << "pki install -c " << conf << " --from <kit>\n";
    }
    if (needs_identity_or_trust(c)) {
        s << step++ << ". Activer la génération PKI installée (nom affiché par pki install, par exemple v1) :\n"
          << "     " << tool << "pki activate -c " << conf << " v1\n";
    }
    s << step++ << ". Droits des fichiers : docs/INSTALLATION.md §4.4"
      << (windows ? " (icacls, après l'installation du service)" : "") << ".\n"
      << step++ << ". Service :\n"
      << "     " << tool << "service install --instance " << c.instance << " --boot\n"
      << "     " << tool << "start --instance " << c.instance << "\n"
      << "     " << tool << "status --instance " << c.instance << "\n";
    const auto warnings = export_warnings(r);
    if (!warnings.empty()) {
        s << "\nPoints d'attention :\n";
        for (const auto& w : warnings) s << "- " << w << "\n";
    }
    return s.str();
}

}  // namespace

std::string default_config_path(TargetPlatform platform, const std::string& instance) {
    return platform == TargetPlatform::windows_host ? "C:\\ProgramData\\tlsrelay\\" + instance + ".yaml"
                                                    : "/etc/tlsrelay/" + instance + ".yaml";
}

std::vector<std::string> export_warnings(const ExportRequest& r) {
    std::vector<std::string> out;
    const auto& c = r.config;
    auto check_path = [&](const std::string& what, const std::string& path) {
        if (!is_absolute_for(r.platform, path)) {
            out.push_back(what + " « " + path +
                          " » : chemin relatif, résolu par le service depuis son répertoire de travail ; "
                          "indiquer un chemin absolu");
        }
    };
    if (c.whitelist) check_path("whitelist.file", c.whitelist->file);
    if (c.credentials) check_path("credentials.pki_root", c.credentials->pki_root);
    if (c.logging.output != "stderr") check_path("logging.output", c.logging.output);
    if (c.admin.endpoint) {
        out.push_back("admin.endpoint est défini : pour un service, laisser le point d'accès par défaut "
                      "(les commandes --instance le retrouvent)");
    }
    if (r.crl_file && !(pki::requirements_for(c) && pki::requirements_for(c)->trust)) {
        out.push_back("CRL fournie, mais cette instance ne vérifie pas le certificat de ses pairs : sans objet");
    }
    if (r.kit_dir && !pki::requirements_for(c)) out.push_back("kit PKI fourni, mais aucun port tls ou mtls n'est configuré");
    return out;
}

fs::path export_package(const ExportRequest& r) {
    const auto& c = r.config;
    const auto dir = r.out_dir / c.instance;
    std::error_code ec;
    if (fs::exists(dir, ec) && !fs::is_empty(dir, ec)) {
        throw std::runtime_error(dir.string() + " existe déjà et n'est pas vide");
    }
    if (r.kit_dir) {
        for (const char* f : kKitFiles) {
            if (!fs::is_regular_file(*r.kit_dir / f, ec)) {
                throw std::runtime_error("kit PKI incomplet : " + (*r.kit_dir / f).string() + " manquant");
            }
        }
    }
    std::optional<std::string> crl;
    if (r.crl_file) {
        crl = read_text(*r.crl_file);
        if (!crl || crl->find("-----BEGIN X509 CRL-----") == std::string::npos) {
            throw std::runtime_error("fichier de CRL illisible : " + r.crl_file->string());
        }
    }
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("création impossible : " + dir.string() + " : " + ec.message());

    const auto conf = default_config_path(r.platform, c.instance);
    write(dir / (c.instance + ".yaml"), r.config_text);
    if (r.whitelist_text) write(dir / "whitelist.yaml", *r.whitelist_text);
    if (r.kit_dir) {
        fs::create_directories(dir / "kit", ec);
        for (const char* f : kKitFiles) fs::copy_file(*r.kit_dir / f, dir / "kit" / f, fs::copy_options::overwrite_existing);
    }
    if (crl) write(dir / "crl.pem", *crl);
    if (r.platform == TargetPlatform::linux_host) {
        write(dir / "install.sh", linux_script(r, conf));
        fs::permissions(dir / "install.sh", fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                        fs::perm_options::add, ec);
    } else {
        write(dir / "install.ps1", windows_script(r));
    }
    write(dir / "LISEZMOI.txt", readme(r, conf));
    return dir;
}

}  // namespace tlsrelay::admin
