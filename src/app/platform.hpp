#pragma once

// Intégration au gestionnaire de services du système (SPEC §10) :
// systemd (unité modèle tlsrelay@.service) sous Linux, gestionnaire de
// services (service tlsrelay-<instance>) sous Windows.

#include "tlsrelay/units.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace tlsrelay::app {

// Fichier de configuration par défaut d'une instance :
// /etc/tlsrelay/<instance>.yaml ou %ProgramData%\tlsrelay\<instance>.yaml.
std::filesystem::path default_config_path(const std::string& instance);

struct InstallOptions {
    std::string instance;
    std::filesystem::path config;  // chemin absolu, configuration déjà validée
    bool boot = false;             // démarrage automatique avec le système
    Duration shutdown_timeout{};   // limits.shutdown_timeout de la configuration
};

// Chaque fonction affiche ce qu'elle fait et retourne un code de sortie.
int service_install(const InstallOptions& options);
int service_uninstall(const std::string& instance);
bool service_installed(const std::string& instance);
// Démarre le service installé (sans attendre le canal d'administration).
int service_start(const std::string& instance, Duration timeout);
// Attend que le gestionnaire de services constate l'arrêt de l'instance.
void service_wait_stopped(const std::string& instance, Duration timeout);
// Arrêt forcé par le gestionnaire de services (si le canal ne répond plus).
int service_force_kill(const std::string& instance);

// Lien entre l'instance en cours d'exécution et le gestionnaire de services.
class ServiceControl {
public:
    virtual ~ServiceControl() = default;
    // Ports ouverts : le service est en marche. request_stop déclenche l'arrêt propre.
    virtual void ready(std::function<void()> request_stop) = 0;
};

#ifdef _WIN32
// Journal d'un service dont la configuration écrit sur stderr :
// %ProgramData%\tlsrelay\logs\<instance>.log.
std::filesystem::path default_service_log(const std::string& instance);

// Point d'entrée du processus lancé par le gestionnaire de services Windows
// (commande interne service-run). run exécute l'instance jusqu'à son arrêt.
int service_dispatch(const std::string& instance, std::function<int(ServiceControl&)> run);
#endif

}  // namespace tlsrelay::app
