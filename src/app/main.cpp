// Point d'entrée de tlsrelay (SPEC §10). Commandes de la phase 1 :
//   tlsrelay run -c <config> [-v|-vv|-q]
//   tlsrelay check-config -c <config>
//   tlsrelay version

#include "tlsrelay/config.hpp"
#include "tlsrelay/logging.hpp"
#include "tlsrelay/openssl_info.hpp"
#include "tlsrelay/relay/service.hpp"
#include "tlsrelay/version.hpp"

#include <CLI/CLI.hpp>

#include <cstdio>
#include <iostream>
#include <optional>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

// Codes de sortie
constexpr int kExitOk = 0;
constexpr int kExitRuntime = 1;
constexpr int kExitConfig = 2;

void print_issues(const tlsrelay::LoadResult& result) {
    for (const auto& e : result.errors) std::cerr << "erreur : " << e.path << " : " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "avertissement : " << w.path << " : " << w.message << '\n';
}

int cmd_check_config(const std::string& path) {
    const auto result = tlsrelay::load_config_file(path);
    print_issues(result);
    if (!result.config) {
        std::cerr << result.errors.size() << " erreur(s) dans " << path << '\n';
        return kExitConfig;
    }
    std::cout << "configuration valide : " << path << '\n';
    return kExitOk;
}

int cmd_run(const std::string& path, std::optional<tlsrelay::LogLevel> cli_level) {
    using namespace tlsrelay;

    const auto result = load_config_file(path);
    print_issues(result);
    if (!result.config) return kExitConfig;
    const Config& config = *result.config;

    if (!openssl_runtime_supported()) {
        std::cerr << "erreur : OpenSSL 3.0 ou plus récent est requis (version chargée : " << openssl_runtime_version()
                  << ")\n";
        return kExitRuntime;
    }

    try {
        logging::init(config.logging, cli_level);
    } catch (const std::exception& e) {
        std::cerr << "erreur : " << e.what() << '\n';
        return kExitRuntime;
    }
    logging::config().info("tlsrelay {} : configuration chargée depuis {} (mode={}, instance={})", kVersion, path,
                           to_string(config.mode), config.instance);
    logging::config().info("OpenSSL chargé : {}", openssl_runtime_version());

    try {
        relay::Service service(config);
        return service.run();
    } catch (const std::exception& e) {
        logging::config().error("{}", e.what());
        return kExitRuntime;
    }
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    tlsrelay::logging::init_default();

    CLI::App app{"tlsrelay : relais TCP clair / TLS 1.3 / mTLS"};
    app.require_subcommand(1);
    app.set_help_all_flag("--help-all", "Aide de toutes les commandes");

    std::string config_path;
    int verbosity = 0;
    bool quiet = false;

    auto* run = app.add_subcommand("run", "Exécute le relais au premier plan (Ctrl+C pour arrêter)");
    run->add_option("-c,--config", config_path, "Fichier de configuration")->required();
    auto* verbose_flag = run->add_flag("-v,--verbose", verbosity, "Mode verbose : -v (debug), -vv (trace)");
    run->add_flag("-q,--quiet", quiet, "Erreurs uniquement")->excludes(verbose_flag);

    auto* check = app.add_subcommand("check-config", "Valide un fichier de configuration sans le charger");
    check->add_option("-c,--config", config_path, "Fichier de configuration")->required();

    auto* version = app.add_subcommand("version", "Affiche la version de tlsrelay et d'OpenSSL");

    CLI11_PARSE(app, argc, argv);

    if (*version) {
        std::cout << "tlsrelay " << tlsrelay::kVersion << '\n'
                  << "OpenSSL " << tlsrelay::openssl_runtime_version() << '\n';
        return kExitOk;
    }
    if (*check) return cmd_check_config(config_path);

    std::optional<tlsrelay::LogLevel> level;
    if (quiet) level = tlsrelay::LogLevel::error;
    else if (verbosity == 1) level = tlsrelay::LogLevel::debug;
    else if (verbosity >= 2) level = tlsrelay::LogLevel::trace;
    return cmd_run(config_path, level);
}
