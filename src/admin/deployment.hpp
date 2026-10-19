#pragma once

// Deployment package of an instance (tlsrelay-admin export): a
// directory to copy to the instance's machine, with the configuration,
// the whitelist, the optional PKI kit and CRLs, an installation script
// and its instructions.
//
//   <output>/<instance>/
//     <instance>.yaml          configuration
//     whitelist.yaml           whitelist (server)
//     kit/                     kit produced by "ca sign" (optional)
//     crl.pem                  CRLs published by the CA (optional)
//     install.sh | install.ps1 installation (Linux | Windows)
//     README.txt               steps, in order

#include "tlsrelay/config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace tlsrelay::admin {

enum class TargetPlatform { linux_host, windows_host };

struct ExportRequest {
    std::filesystem::path out_dir;  // the package is created in out_dir/<instance>
    TargetPlatform platform = TargetPlatform::linux_host;
    Config config;                 // valid configuration
    std::string config_text;       // saved text (to_yaml)
    std::optional<std::string> whitelist_text;  // server
    std::optional<std::filesystem::path> kit_dir;
    std::optional<std::filesystem::path> crl_file;
};

// Points to report before the export (relative paths, PKI without a kit, etc.).
std::vector<std::string> export_warnings(const ExportRequest& request);

// Creates the package; returns its directory. Refuses an existing, non-empty
// package directory, an incomplete kit or an unreadable CRL file.
// Throws std::runtime_error.
std::filesystem::path export_package(const ExportRequest& request);

// Location of an instance's configuration on the target machine
// (the one used by "--instance" and "service install").
std::string default_config_path(TargetPlatform platform, const std::string& instance);

}  // namespace tlsrelay::admin
