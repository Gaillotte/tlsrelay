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
    // C:\..., C:/..., \\server\share
    return (path.size() >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) || path.rfind("\\\\", 0) == 0;
}

// Single-quoted string for sh ('…'; a single quote becomes '\'').
std::string sh_quote(const std::string& text) {
    std::string out = "'";
    for (char c : text) out += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return out + "'";
}

// Single-quoted string for PowerShell (a single quote is doubled).
std::string ps_quote(const std::string& text) {
    std::string out = "'";
    for (char c : text) out += c == '\'' ? std::string("''") : std::string(1, c);
    return out + "'";
}

void write(const fs::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    out.close();
    if (!out) throw std::runtime_error("cannot write: " + path.string());
}

bool needs_identity_or_trust(const Config& config) { return pki::requirements_for(config).has_value(); }

std::string linux_script(const ExportRequest& r, const std::string& conf) {
    const auto& c = r.config;
    std::ostringstream s;
    s << "#!/bin/sh\n"
      << "# Installation of instance " << c.instance << " (package produced by tlsrelay-admin).\n"
      << "# Run as root on the instance's machine, from this directory.\n"
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
    s << "echo \"instance " << c.instance << " installed: follow README.txt for the next steps\"\n";
    return s.str();
}

std::string windows_script(const ExportRequest& r) {
    const auto& c = r.config;
    std::ostringstream s;
    // UTF-8 with BOM: read correctly by Windows PowerShell 5.1.
    s << "\xEF\xBB\xBF"
      << "# Installation of instance " << c.instance << " (package produced by tlsrelay-admin).\n"
      << "# Run in an administrator PowerShell, from this directory.\n"
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
    s << "Write-Host \"instance " << c.instance << " installed: follow README.txt for the next steps\"\n";
    return s.str();
}

std::string readme(const ExportRequest& r, const std::string& conf) {
    const auto& c = r.config;
    const bool windows = r.platform == TargetPlatform::windows_host;
    // tlsrelay is not in the PATH on Windows (INSTALLATION §3).
    const std::string tool = windows ? "& \"$env:ProgramFiles\\tlsrelay\\bin\\tlsrelay.exe\" " : "sudo tlsrelay ";
    std::ostringstream s;
    if (windows) s << "\xEF\xBB\xBF";
    s << "Deployment package of instance \"" << c.instance << "\" (" << to_string(c.mode) << " mode)\n"
      << "Produced by tlsrelay-admin. See also docs/INSTALLATION.md.\n\n"
      << "1. Install the tlsrelay package on the machine, then copy this directory.\n"
      << "2. Run " << (windows ? "install.ps1 in an administrator PowerShell" : "sudo sh install.sh")
      << ": configuration copied to " << conf;
    if (r.whitelist_text && c.whitelist) s << ", whitelist to " << c.whitelist->file;
    s << ", configuration check";
    if (r.kit_dir) s << ", PKI kit installation";
    if (r.crl_file) s << ", CRL installation";
    s << ".\n";
    int step = 3;
    if (needs_identity_or_trust(c) && !r.kit_dir) {
        s << step++ << ". PKI: create the key and the signing request on this machine:\n"
          << "     " << tool << "pki gen-csr -c " << conf << " --subject \"CN=...,O=...\""
          << (c.mode == Mode::server ? " --san <DNS name or IP>" : "") << "\n"
          << "   then have request.csr signed by the CA (tlsrelay-admin or tlsrelay ca sign) and install the kit:\n"
          << "     " << tool << "pki install -c " << conf << " --from <kit>\n";
    }
    if (needs_identity_or_trust(c)) {
        s << step++ << ". Activate the installed PKI generation (name shown by pki install, for example v1):\n"
          << "     " << tool << "pki activate -c " << conf << " v1\n";
    }
    s << step++ << ". File permissions: docs/INSTALLATION.md §4.4"
      << (windows ? " (icacls, after installing the service)" : "") << ".\n";
    s << step++ << ". Service:\n"
      << "     " << tool << "service install --instance " << c.instance << " --boot\n"
      << "     " << tool << "start --instance " << c.instance << "\n"
      << "     " << tool << "status --instance " << c.instance << "\n";
    const auto warnings = export_warnings(r);
    if (!warnings.empty()) {
        s << "\nPoints to note:\n";
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
            out.push_back(what + " \"" + path +
                          "\": relative path, resolved by the service from its working directory; "
                          "give an absolute path");
        }
    };
    if (c.whitelist) check_path("whitelist.file", c.whitelist->file);
    if (c.credentials) check_path("credentials.pki_root", c.credentials->pki_root);
    if (c.logging.output != "stderr") check_path("logging.output", c.logging.output);
    if (c.admin.endpoint) {
        out.push_back("admin.endpoint is set: for a service, keep the default endpoint "
                      "(the --instance commands find it)");
    }
    if (r.crl_file && !(pki::requirements_for(c) && pki::requirements_for(c)->trust)) {
        out.push_back("CRL provided, but this instance does not verify its peers' certificates: not applicable");
    }
    if (r.kit_dir && !pki::requirements_for(c)) out.push_back("PKI kit provided, but no tls or mtls port is configured");
    return out;
}

fs::path export_package(const ExportRequest& r) {
    const auto& c = r.config;
    const auto dir = r.out_dir / c.instance;
    std::error_code ec;
    if (fs::exists(dir, ec) && !fs::is_empty(dir, ec)) {
        throw std::runtime_error(dir.string() + " already exists and is not empty");
    }
    if (r.kit_dir) {
        for (const char* f : kKitFiles) {
            if (!fs::is_regular_file(*r.kit_dir / f, ec)) {
                throw std::runtime_error("incomplete PKI kit: " + (*r.kit_dir / f).string() + " missing");
            }
        }
    }
    std::optional<std::string> crl;
    if (r.crl_file) {
        crl = read_text(*r.crl_file);
        if (!crl || crl->find("-----BEGIN X509 CRL-----") == std::string::npos) {
            throw std::runtime_error("unreadable CRL file: " + r.crl_file->string());
        }
    }
    fs::create_directories(dir, ec);
    if (ec) throw std::runtime_error("cannot create: " + dir.string() + ": " + ec.message());

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
    write(dir / "README.txt", readme(r, conf));
    return dir;
}

}  // namespace tlsrelay::admin
