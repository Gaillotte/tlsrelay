// Intégration systemd : unité modèle tlsrelay@.service et, par instance, un
// complément (drop-in) qui désigne la configuration et le délai d'arrêt.

#include "platform.hpp"

#include <grp.h>
#include <pwd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <system_error>
#include <vector>

namespace tlsrelay::app {
namespace {

namespace fs = std::filesystem;

constexpr int kExitOk = 0;
constexpr int kExitRuntime = 1;

const fs::path kUnitDir = "/etc/systemd/system";
const fs::path kTemplate = kUnitDir / "tlsrelay@.service";

fs::path dropin_dir(const std::string& instance) { return kUnitDir / ("tlsrelay@" + instance + ".service.d"); }
fs::path dropin(const std::string& instance) { return dropin_dir(instance) / "10-tlsrelay.conf"; }
std::string unit(const std::string& instance) { return "tlsrelay@" + instance + ".service"; }

// Exécute une commande sans interpréteur de commandes ; retourne son code de sortie.
int run(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    const pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        ::execvp(argv[0], argv.data());
        _exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int systemctl(std::vector<std::string> args) {
    args.insert(args.begin(), "systemctl");
    std::string line;
    for (const auto& a : args) line += (line.empty() ? "" : " ") + a;
    const int code = run(args);
    if (code != 0) std::cerr << "erreur : « " << line << " » a échoué (code " << code << ")\n";
    return code;
}

fs::path self_path() {
    std::error_code ec;
    auto p = fs::read_symlink("/proc/self/exe", ec);
    return ec ? fs::path("/usr/bin/tlsrelay") : p;
}

bool require_root() {
    if (::geteuid() == 0) return true;
    std::cerr << "erreur : droits root nécessaires (sudo)\n";
    return false;
}

// Unité modèle : un processus par instance, durci (compte dédié, système de
// fichiers en lecture seule sauf journaux et état, seule capacité : ports < 1024).
std::string template_unit(const fs::path& exe) {
    const auto bin = exe.string();
    return "# Généré par « tlsrelay service install ». Configuration propre à chaque instance :\n"
           "# /etc/systemd/system/tlsrelay@<instance>.service.d/10-tlsrelay.conf\n"
           "[Unit]\n"
           "Description=tlsrelay, relais TCP clair / TLS 1.3 / mTLS (instance %i)\n"
           "Documentation=https://github.com/Gaillotte/tlsrelay\n"
           "After=network-online.target\n"
           "Wants=network-online.target\n"
           "\n"
           "[Service]\n"
           "Type=notify\n"
           "Environment=TLSRELAY_CONFIG=/etc/tlsrelay/%i.yaml\n"
           "ExecStart=" + bin + " run --instance %i -c ${TLSRELAY_CONFIG}\n"
           "ExecReload=" + bin + " reload --instance %i\n"
           "# Arrêt : SIGTERM, drain des canaux (limits.shutdown_timeout), puis arrêt.\n"
           "KillMode=mixed\n"
           "TimeoutStopSec=60\n"
           "Restart=on-failure\n"
           "RestartSec=2s\n"
           "User=tlsrelay\n"
           "Group=tlsrelay\n"
           "RuntimeDirectory=tlsrelay\n"
           "RuntimeDirectoryMode=0750\n"
           "RuntimeDirectoryPreserve=yes\n"
           "LogsDirectory=tlsrelay\n"
           "StateDirectory=tlsrelay\n"
           "UMask=0027\n"
           "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
           "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
           "NoNewPrivileges=yes\n"
           "ProtectSystem=strict\n"
           "ProtectHome=yes\n"
           "PrivateTmp=yes\n"
           "PrivateDevices=yes\n"
           "ProtectKernelTunables=yes\n"
           "ProtectKernelModules=yes\n"
           "ProtectKernelLogs=yes\n"
           "ProtectControlGroups=yes\n"
           "ProtectClock=yes\n"
           "ProtectHostname=yes\n"
           "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
           "RestrictNamespaces=yes\n"
           "RestrictRealtime=yes\n"
           "RestrictSUIDSGID=yes\n"
           "LockPersonality=yes\n"
           "MemoryDenyWriteExecute=yes\n"
           "SystemCallArchitectures=native\n"
           "\n"
           "[Install]\n"
           "WantedBy=multi-user.target\n";
}

bool write_file(const fs::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    if (!out) {
        std::cerr << "erreur : écriture impossible : " << path << '\n';
        return false;
    }
    return true;
}

}  // namespace

fs::path default_config_path(const std::string& instance) { return fs::path("/etc/tlsrelay") / (instance + ".yaml"); }

bool service_installed(const std::string& instance) {
    std::error_code ec;
    return fs::exists(dropin(instance), ec);
}

int service_install(const InstallOptions& options) {
    if (!require_root()) return kExitRuntime;

    // Compte système dédié.
    if (!::getpwnam("tlsrelay")) {
        std::cout << "création du compte système tlsrelay\n";
        if (run({"useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell",
                 "/usr/sbin/nologin", "--user-group", "tlsrelay"}) != 0) {
            std::cerr << "erreur : création du compte tlsrelay impossible (useradd)\n";
            return kExitRuntime;
        }
    }

    std::error_code ec;
    if (!write_file(kTemplate, template_unit(self_path()))) return kExitRuntime;
    fs::create_directories(dropin_dir(options.instance), ec);
    // Délai d'arrêt de systemd : drain de la configuration plus une marge.
    const auto stop_seconds = std::chrono::duration_cast<std::chrono::seconds>(options.shutdown_timeout).count() + 15;
    if (!write_file(dropin(options.instance), "# Généré par « tlsrelay service install ».\n[Service]\n"
                                              "Environment=TLSRELAY_CONFIG=" + options.config.string() + "\n"
                                              "TimeoutStopSec=" + std::to_string(stop_seconds) + "\n")) {
        return kExitRuntime;
    }
    if (systemctl({"daemon-reload"}) != 0) return kExitRuntime;
    if (options.boot && systemctl({"enable", unit(options.instance)}) != 0) return kExitRuntime;

    std::cout << "service " << unit(options.instance) << " installé (configuration " << options.config.string()
              << (options.boot ? ", démarrage au boot" : ", démarrage manuel") << ")\n"
              << "le compte tlsrelay doit pouvoir lire la configuration, la liste blanche et la PKI\n"
              << "démarrage : tlsrelay start --instance " << options.instance << '\n';
    return kExitOk;
}

int service_uninstall(const std::string& instance) {
    if (!require_root()) return kExitRuntime;
    if (!service_installed(instance)) {
        std::cerr << "erreur : le service " << unit(instance) << " n'est pas installé\n";
        return kExitRuntime;
    }
    // Arrêt (avec drain) et retrait du démarrage au boot.
    systemctl({"disable", "--now", unit(instance)});
    std::error_code ec;
    fs::remove_all(dropin_dir(instance), ec);
    systemctl({"daemon-reload"});
    std::cout << "service " << unit(instance) << " désinstallé\n";
    return kExitOk;
}

int service_start(const std::string& instance, Duration) {
    // Type=notify : systemctl attend que l'instance soit prête (ports ouverts).
    return systemctl({"start", unit(instance)}) == 0 ? kExitOk : kExitRuntime;
}

void service_wait_stopped(const std::string&, Duration) {
    // systemd met en file un démarrage demandé pendant la fin de l'arrêt.
}

int service_force_kill(const std::string& instance) {
    return systemctl({"kill", "--signal=SIGKILL", unit(instance)}) == 0 ? kExitOk : kExitRuntime;
}

}  // namespace tlsrelay::app
