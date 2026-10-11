// Point d'entrée de tlsrelay (SPEC §10). Commandes disponibles :
//   tlsrelay run -c <config> [--instance N] [-v|-vv|-q]
//   tlsrelay check-config -c <config>
//   tlsrelay check-pki -c <config> [génération]
//   tlsrelay pki activate -c <config> <génération> [--force]
//   tlsrelay status|channels|metrics|kill|log-reopen [cible]
//   tlsrelay stop [cible] [--timeout durée]
//   tlsrelay reload [cible] [--kill-old]
//   tlsrelay log-level [cible] <niveau|catégorie=niveau>
//   tlsrelay start|restart --instance N [--timeout durée]
//   tlsrelay service install --instance N [-c config] [--boot]
//   tlsrelay service uninstall --instance N
//   tlsrelay version
// cible : --instance N (défaut : default), -c <config> ou --admin <point d'accès>.

#include "platform.hpp"

#include "tlsrelay/admin/admin.hpp"
#include "tlsrelay/config.hpp"
#include "tlsrelay/logging.hpp"
#include "tlsrelay/openssl_info.hpp"
#include "tlsrelay/pki/generation.hpp"
#include "tlsrelay/relay/service.hpp"
#include "tlsrelay/version.hpp"

#include <CLI/CLI.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>

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

// Charge la configuration et en déduit les exigences PKI ; nullopt si erreur (déjà affichée).
std::optional<std::pair<tlsrelay::Config, tlsrelay::pki::Requirements>> pki_context(const std::string& path) {
    const auto result = tlsrelay::load_config_file(path);
    print_issues(result);
    if (!result.config) return std::nullopt;
    const auto req = tlsrelay::pki::requirements_for(*result.config);
    if (!req || !result.config->credentials) {
        std::cerr << "erreur : aucun port tls ou mtls configuré dans " << path << '\n';
        return std::nullopt;
    }
    return std::pair{*result.config, *req};
}

int cmd_check_pki(const std::string& config_path, std::string name) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    const auto& root = ctx->first.credentials->pki_root;
    if (name.empty()) {
        std::ifstream in(std::filesystem::path(root) / "current");
        std::getline(in, name);
    }
    const auto result = tlsrelay::pki::check_candidate(root, name, ctx->second);
    for (const auto& e : result.errors) std::cerr << "erreur : " << e.path << " : " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "avertissement : " << w.path << " : " << w.message << '\n';
    if (!result.generation) {
        std::cerr << "génération « " << name << " » refusée\n";
        return kExitConfig;
    }
    const auto& gen = *result.generation;
    std::cout << "génération « " << name << " » valide";
    if (gen.cert) std::cout << " : certificat " << tlsrelay::tls::subject_of(gen.cert.get()) << ", valable jusqu'au "
                            << tlsrelay::tls::not_after_of(gen.cert.get());
    std::cout << '\n';
    return kExitOk;
}

int cmd_pki_activate(const std::string& config_path, const std::string& name, bool force) {
    const auto ctx = pki_context(config_path);
    if (!ctx) return kExitConfig;
    const auto& root = ctx->first.credentials->pki_root;
    const auto result = tlsrelay::pki::check_candidate(root, name, ctx->second);
    for (const auto& e : result.errors) std::cerr << "erreur : " << e.path << " : " << e.message << '\n';
    for (const auto& w : result.warnings) std::cerr << "avertissement : " << w.path << " : " << w.message << '\n';
    if (!result.generation && !force) {
        std::cerr << "génération « " << name << " » non activée (--force pour passer outre)\n";
        return kExitConfig;
    }
    try {
        tlsrelay::pki::activate(root, name);
    } catch (const std::exception& e) {
        std::cerr << "erreur : " << e.what() << '\n';
        return kExitRuntime;
    }
    std::cout << "génération « " << name << " » activée dans " << root
              << " (prise en compte par le service en cours d'exécution à la prochaine surveillance, ou avec SIGHUP)\n";
    return kExitOk;
}

// Exécute une instance jusqu'à son arrêt. instance : nom attendu (vide : celui
// de la configuration). control : gestionnaire de services (nullptr en console).
int run_instance(const std::string& path, std::optional<tlsrelay::LogLevel> cli_level, const std::string& instance,
                 tlsrelay::app::ServiceControl* control) {
    using namespace tlsrelay;

    const auto result = load_config_file(path);
    print_issues(result);
    if (!result.config) return kExitConfig;
    Config config = *result.config;
    if (!instance.empty() && instance != config.instance) {
        std::cerr << "erreur : la configuration " << path << " est celle de l'instance « " << config.instance
                  << " » et non de « " << instance << " »\n";
        return kExitConfig;
    }
#ifdef _WIN32
    // Un service Windows n'a pas de console : journal dans %ProgramData%.
    if (control && config.logging.output == "stderr") {
        config.logging.output = app::default_service_log(config.instance).string();
    }
#endif

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
        relay::ServiceOptions options;
#ifdef _WIN32
        options.handle_signals = control == nullptr;  // un service reçoit ses ordres du gestionnaire
#endif
        options.config_path = std::filesystem::absolute(path).string();
        relay::Service service(config, options);
        if (control) control->ready([&service] { service.request_stop(); });
        return service.run();
    } catch (const std::exception& e) {
        logging::config().error("{}", e.what());
        // Journal dans un fichier : l'erreur de démarrage est aussi affichée.
        if (config.logging.output != "stderr" && !control) std::cerr << "erreur : " << e.what() << '\n';
        return kExitRuntime;
    }
}

// Instance visée par une commande d'administration.
struct Target {
    std::string instance;
    std::string config;
    std::string admin;

    // Point d'accès du canal ; vide si la configuration est illisible (erreur affichée).
    std::string endpoint() const {
        if (!admin.empty()) return admin;
        if (!config.empty()) {
            const auto result = tlsrelay::load_config_file(config);
            if (!result.config) {
                print_issues(result);
                return {};
            }
            return tlsrelay::admin::endpoint_for(*result.config);
        }
        return tlsrelay::admin::default_endpoint(instance.empty() ? "default" : instance);
    }

    std::string name() const {
        if (!config.empty()) {
            if (const auto result = tlsrelay::load_config_file(config); result.config) return result.config->instance;
        }
        return instance.empty() ? "default" : instance;
    }
};

constexpr auto kCallTimeout = std::chrono::seconds(30);

// Envoie une commande et affiche la réponse. Retourne le code de sortie.
int send_command(const std::string& endpoint, const std::string& request, bool print = true) {
    if (endpoint.empty()) return kExitConfig;
    const auto result = tlsrelay::admin::call(endpoint, request, kCallTimeout);
    if (!result.reply) {
        std::cerr << "erreur : " << result.error << '\n';
        return kExitRuntime;
    }
    if (print) (result.reply->ok ? std::cout : std::cerr) << result.reply->body;
    return result.reply->ok ? kExitOk : kExitRuntime;
}

// Attend que l'instance ne réponde plus (arrêtée).
bool wait_stopped(const std::string& endpoint, tlsrelay::Duration timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (tlsrelay::admin::call(endpoint, "ping", std::chrono::seconds(2)).unreachable) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

// Attend que l'instance réponde (démarrée).
bool wait_running(const std::string& endpoint, tlsrelay::Duration timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (tlsrelay::admin::call(endpoint, "ping", std::chrono::seconds(2)).reply) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

int cmd_stop(const Target& target, const std::string& timeout_text) {
    const auto endpoint = target.endpoint();
    if (endpoint.empty()) return kExitConfig;
    std::string request = "stop";
    tlsrelay::Duration wait = std::chrono::minutes(1);
    if (!timeout_text.empty()) {
        const auto timeout = tlsrelay::parse_duration(timeout_text);
        if (!timeout) {
            std::cerr << "erreur : délai invalide « " << timeout_text << " »\n";
            return kExitConfig;
        }
        request += " " + timeout_text;
        wait = *timeout + std::chrono::seconds(15);
    }
    const auto result = tlsrelay::admin::call(endpoint, request, kCallTimeout);
    if (!result.reply) {
        if (result.unreachable) {
            std::cout << "instance « " << target.name() << " » déjà arrêtée\n";
            return kExitOk;
        }
        std::cerr << "erreur : " << result.error << '\n';
        return kExitRuntime;
    }
    std::cout << result.reply->body;
    if (!result.reply->ok) return kExitRuntime;
    if (!wait_stopped(endpoint, wait)) {
        std::cerr << "erreur : l'instance ne s'est pas arrêtée dans le délai (tlsrelay kill pour forcer)\n";
        return kExitRuntime;
    }
    if (tlsrelay::app::service_installed(target.name())) {
        tlsrelay::app::service_wait_stopped(target.name(), std::chrono::seconds(10));
    }
    std::cout << "instance « " << target.name() << " » arrêtée\n";
    return kExitOk;
}

int cmd_kill(const Target& target) {
    const auto endpoint = target.endpoint();
    if (endpoint.empty()) return kExitConfig;
    const auto result = tlsrelay::admin::call(endpoint, "kill", std::chrono::seconds(5));
    if (result.reply && wait_stopped(endpoint, std::chrono::seconds(10))) {
        if (tlsrelay::app::service_installed(target.name())) {
            tlsrelay::app::service_wait_stopped(target.name(), std::chrono::seconds(10));
        }
        std::cout << "instance « " << target.name() << " » arrêtée immédiatement\n";
        return kExitOk;
    }
    if (result.unreachable && !tlsrelay::app::service_installed(target.name())) {
        std::cout << "instance « " << target.name() << " » déjà arrêtée\n";
        return kExitOk;
    }
    // Canal muet : arrêt forcé par le gestionnaire de services.
    if (tlsrelay::app::service_installed(target.name())) {
        std::cerr << "canal d'administration sans réponse : arrêt forcé du service\n";
        return tlsrelay::app::service_force_kill(target.name());
    }
    std::cerr << "erreur : " << (result.reply ? "l'instance ne s'est pas arrêtée" : result.error) << '\n';
    return kExitRuntime;
}

int cmd_start(const std::string& instance, tlsrelay::Duration timeout) {
    if (!tlsrelay::app::service_installed(instance)) {
        std::cerr << "erreur : l'instance « " << instance
                  << " » n'est pas installée comme service (tlsrelay service install, ou tlsrelay run)\n";
        return kExitRuntime;
    }
    const auto endpoint = tlsrelay::admin::default_endpoint(instance);
    if (tlsrelay::admin::call(endpoint, "ping", std::chrono::seconds(2)).reply) {
        std::cout << "instance « " << instance << " » déjà démarrée\n";
        return kExitOk;
    }
    if (const int code = tlsrelay::app::service_start(instance, timeout); code != kExitOk) return code;
    if (!wait_running(endpoint, timeout)) {
        std::cerr << "erreur : le service est lancé mais son canal d'administration ne répond pas (" << endpoint
                  << ")\n";
        return kExitRuntime;
    }
    std::cout << "instance « " << instance << " » démarrée\n";
    return kExitOk;
}

int cmd_install(const std::string& instance, std::string config_path, bool boot) {
    if (!tlsrelay::valid_instance_name(instance)) {
        std::cerr << "erreur : nom d'instance invalide « " << instance << " »\n";
        return kExitConfig;
    }
    if (config_path.empty()) config_path = tlsrelay::app::default_config_path(instance).string();
    const auto absolute = std::filesystem::absolute(config_path);
    const auto result = tlsrelay::load_config_file(absolute);
    print_issues(result);
    if (!result.config) return kExitConfig;
    if (result.config->instance != instance) {
        std::cerr << "erreur : " << absolute.string() << " déclare l'instance « " << result.config->instance
                  << " » (instance: " << instance << " attendu)\n";
        return kExitConfig;
    }
    if (result.config->admin.endpoint) {
        std::cerr << "erreur : un service utilise le canal d'administration par défaut : retirer admin.endpoint\n";
        return kExitConfig;
    }
    return tlsrelay::app::service_install(
        {instance, absolute, boot, result.config->limits.shutdown_timeout});
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
    std::string run_instance_name;
    run->add_option("--instance", run_instance_name, "Nom d'instance attendu dans la configuration (services)");

    auto* check = app.add_subcommand("check-config", "Valide un fichier de configuration sans le charger");
    check->add_option("-c,--config", config_path, "Fichier de configuration")->required();

    std::string generation;
    bool force = false;
    auto* check_pki = app.add_subcommand("check-pki", "Valide une génération PKI (par défaut la génération courante)");
    check_pki->add_option("-c,--config", config_path, "Fichier de configuration")->required();
    check_pki->add_option("generation", generation, "Nom de la génération (ex. v2)");

    auto* pki = app.add_subcommand("pki", "Gestion de la PKI");
    pki->require_subcommand(1);
    auto* activate = pki->add_subcommand("activate", "Active une génération (remplace le fichier current)");
    activate->add_option("-c,--config", config_path, "Fichier de configuration")->required();
    activate->add_option("generation", generation, "Nom de la génération à activer (ex. v2)")->required();
    activate->add_flag("--force", force, "Active même si les contrôles échouent (urgence uniquement)");

    auto* version = app.add_subcommand("version", "Affiche la version de tlsrelay et d'OpenSSL");

    // Commandes vers une instance en cours d'exécution (canal d'administration).
    Target target;
    auto add_target = [&target](CLI::App* cmd) {
        auto* inst = cmd->add_option("--instance", target.instance, "Nom de l'instance (défaut : default)");
        auto* cfg = cmd->add_option("-c,--config", target.config, "Configuration de l'instance");
        auto* adm = cmd->add_option("--admin", target.admin, "Point d'accès du canal d'administration");
        inst->excludes(cfg)->excludes(adm);
        cfg->excludes(adm);
    };
    auto* status = app.add_subcommand("status", "État de l'instance : PID, durée, OpenSSL, génération PKI, canaux");
    add_target(status);
    auto* channels = app.add_subcommand("channels", "Liste des canaux ouverts");
    add_target(channels);
    auto* metrics = app.add_subcommand("metrics", "Métriques au format texte Prometheus");
    add_target(metrics);
    std::string timeout_text;
    auto* stop = app.add_subcommand("stop", "Arrêt propre : drain des canaux, puis arrêt");
    add_target(stop);
    stop->add_option("--timeout", timeout_text, "Durée maximale du drain (défaut : limits.shutdown_timeout)");
    auto* kill = app.add_subcommand("kill", "Arrêt immédiat, sans drain");
    add_target(kill);
    bool kill_old = false;
    auto* reload = app.add_subcommand("reload", "Recharge la liste blanche, la PKI et les niveaux de journalisation");
    add_target(reload);
    reload->add_flag("--kill-old", kill_old, "Ferme aussi les connexions des générations PKI retirées");
    std::string level_spec;
    auto* log_level = app.add_subcommand("log-level", "Change le niveau de journalisation à chaud");
    add_target(log_level);
    log_level->add_option("niveau", level_spec, "error|info|debug|trace, ou activity=<niveau>, config=<niveau>")
        ->required();
    auto* log_reopen = app.add_subcommand("log-reopen", "Rouvre le fichier de log (après rotation)");
    add_target(log_reopen);

    // Gestionnaire de services (systemd, services Windows).
    std::string instance = "default";
    auto* start = app.add_subcommand("start", "Démarre le service d'une instance installée");
    start->add_option("--instance", instance, "Nom de l'instance (défaut : default)");
    start->add_option("--timeout", timeout_text, "Attente maximale du démarrage (défaut : 30s)");
    auto* restart = app.add_subcommand("restart", "Arrêt propre puis redémarrage du service");
    restart->add_option("--instance", instance, "Nom de l'instance (défaut : default)");
    restart->add_option("--timeout", timeout_text, "Durée maximale du drain");
    auto* service = app.add_subcommand("service", "Installation comme service du système");
    service->require_subcommand(1);
    bool boot = false;
    std::string service_config;
    auto* install = service->add_subcommand("install", "Installe le service (systemd tlsrelay@N, Windows tlsrelay-N)");
    install->add_option("--instance", instance, "Nom de l'instance (défaut : default)");
    install->add_option("-c,--config", service_config, "Configuration (défaut : emplacement standard de l'instance)");
    install->add_flag("--boot", boot, "Démarrage automatique avec le système");
    auto* uninstall = service->add_subcommand("uninstall", "Arrête et désinstalle le service");
    uninstall->add_option("--instance", instance, "Nom de l'instance (défaut : default)");
#ifdef _WIN32
    // Commande interne : processus lancé par le gestionnaire de services.
    auto* service_run = app.add_subcommand("service-run", "")->group("");
    service_run->add_option("--instance", instance)->required();
    service_run->add_option("-c,--config", config_path)->required();
#endif

    CLI11_PARSE(app, argc, argv);

    if (*check_pki) return cmd_check_pki(config_path, generation);
    if (*activate) return cmd_pki_activate(config_path, generation, force);

    if (*version) {
        std::cout << "tlsrelay " << tlsrelay::kVersion << '\n'
                  << "OpenSSL " << tlsrelay::openssl_runtime_version() << '\n';
        return kExitOk;
    }
    if (*check) return cmd_check_config(config_path);

    if (*status) return send_command(target.endpoint(), "status");
    if (*channels) return send_command(target.endpoint(), "channels");
    if (*metrics) return send_command(target.endpoint(), "metrics");
    if (*reload) return send_command(target.endpoint(), kill_old ? "reload --kill-old" : "reload");
    if (*log_level) return send_command(target.endpoint(), "log-level " + level_spec);
    if (*log_reopen) return send_command(target.endpoint(), "log-reopen");
    if (*stop) return cmd_stop(target, timeout_text);
    if (*kill) return cmd_kill(target);

    auto service_timeout = [&]() -> std::optional<tlsrelay::Duration> {
        if (timeout_text.empty()) return std::chrono::seconds(30);
        return tlsrelay::parse_duration(timeout_text);
    };
    if (*start || *restart) {
        if (!tlsrelay::valid_instance_name(instance)) {
            std::cerr << "erreur : nom d'instance invalide « " << instance << " »\n";
            return kExitConfig;
        }
        const auto timeout = service_timeout();
        if (!timeout) {
            std::cerr << "erreur : délai invalide « " << timeout_text << " »\n";
            return kExitConfig;
        }
        if (*restart) {
            if (!tlsrelay::app::service_installed(instance)) {
                std::cerr << "erreur : l'instance « " << instance << " » n'est pas installée comme service\n";
                return kExitRuntime;
            }
            Target t;
            t.instance = instance;
            if (const int code = cmd_stop(t, timeout_text); code != kExitOk) return code;
        }
        return cmd_start(instance, std::chrono::seconds(30));
    }
    if (*install) return cmd_install(instance, service_config, boot);
    if (*uninstall) {
        if (!tlsrelay::valid_instance_name(instance)) {
            std::cerr << "erreur : nom d'instance invalide « " << instance << " »\n";
            return kExitConfig;
        }
        return tlsrelay::app::service_uninstall(instance);
    }
#ifdef _WIN32
    if (*service_run) {
        return tlsrelay::app::service_dispatch(instance, [&](tlsrelay::app::ServiceControl& control) {
            return run_instance(config_path, std::nullopt, instance, &control);
        });
    }
#endif

    std::optional<tlsrelay::LogLevel> level;
    if (quiet) level = tlsrelay::LogLevel::error;
    else if (verbosity == 1) level = tlsrelay::LogLevel::debug;
    else if (verbosity >= 2) level = tlsrelay::LogLevel::trace;
    return run_instance(config_path, level, run_instance_name, nullptr);
}
