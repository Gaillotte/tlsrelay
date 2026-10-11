// Intégration au gestionnaire de services Windows : service tlsrelay-<instance>,
// exécuté sous le compte virtuel NT SERVICE\tlsrelay-<instance> (moindre
// privilège), relancé automatiquement en cas d'échec.

#include "platform.hpp"

#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <system_error>
#include <thread>
#include <vector>

namespace tlsrelay::app {
namespace {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

constexpr int kExitOk = 0;
constexpr int kExitRuntime = 1;

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string error_text(DWORD code) { return std::error_code(static_cast<int>(code), std::system_category()).message(); }

std::wstring service_name(const std::string& instance) { return widen("tlsrelay-" + instance); }
std::wstring account(const std::string& instance) { return L"NT SERVICE\\" + service_name(instance); }

fs::path program_data() {
    PWSTR path = nullptr;
    fs::path result = "C:\\ProgramData";
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path))) result = path;
    CoTaskMemFree(path);
    return result / "tlsrelay";
}

class Handle {
public:
    explicit Handle(SC_HANDLE h = nullptr) : h_(h) {}
    ~Handle() {
        if (h_) CloseServiceHandle(h_);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    SC_HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    SC_HANDLE h_;
};

Handle open_manager(DWORD access) {
    Handle h(OpenSCManagerW(nullptr, nullptr, access));
    if (!h) {
        const DWORD err = GetLastError();
        std::cerr << "erreur : gestionnaire de services inaccessible : " << error_text(err)
                  << (err == ERROR_ACCESS_DENIED ? " (lancer en administrateur)" : "") << '\n';
    }
    return h;
}

Handle open_service(const std::string& instance, DWORD access, bool report = true) {
    Handle manager = open_manager(SC_MANAGER_CONNECT);
    if (!manager) return Handle();
    Handle h(OpenServiceW(manager.get(), service_name(instance).c_str(), access));
    if (!h && report) {
        const DWORD err = GetLastError();
        std::cerr << "erreur : service tlsrelay-" << instance << " : "
                  << (err == ERROR_SERVICE_DOES_NOT_EXIST ? std::string("non installé") : error_text(err)) << '\n';
    }
    return h;
}

std::optional<SERVICE_STATUS_PROCESS> query(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof status,
                              &needed)) {
        return std::nullopt;
    }
    return status;
}

// Attend que le service quitte l'état transitoire pending.
std::optional<SERVICE_STATUS_PROCESS> wait_while(SC_HANDLE service, DWORD pending, Duration timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto status = query(service);
        if (!status || status->dwCurrentState != pending || std::chrono::steady_clock::now() >= deadline) {
            return status;
        }
        std::this_thread::sleep_for(200ms);
    }
}

// Donne au compte du service le droit de modifier un répertoire (journaux).
bool grant_modify(const fs::path& dir, const std::wstring& who) {
    PACL old_acl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old_acl,
                              nullptr, &sd) != ERROR_SUCCESS) {
        return false;
    }
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(who.c_str());
    PACL new_acl = nullptr;
    bool ok = SetEntriesInAclW(1, &ea, old_acl, &new_acl) == ERROR_SUCCESS &&
              SetNamedSecurityInfoW(const_cast<LPWSTR>(dir.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                    nullptr, nullptr, new_acl, nullptr) == ERROR_SUCCESS;
    if (new_acl) LocalFree(new_acl);
    if (sd) LocalFree(sd);
    return ok;
}

std::wstring self_path() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (n < path.size()) {
            path.resize(n);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

}  // namespace

fs::path default_config_path(const std::string& instance) { return program_data() / (instance + ".yaml"); }

fs::path default_service_log(const std::string& instance) { return program_data() / "logs" / (instance + ".log"); }

bool service_installed(const std::string& instance) {
    return static_cast<bool>(open_service(instance, SERVICE_QUERY_STATUS, false));
}

int service_install(const InstallOptions& options) {
    Handle manager = open_manager(SC_MANAGER_CREATE_SERVICE);
    if (!manager) return kExitRuntime;

    const std::wstring command = L"\"" + self_path() + L"\" service-run --instance " + widen(options.instance) +
                                 L" -c \"" + options.config.wstring() + L"\"";
    const std::wstring display = widen("tlsrelay (" + options.instance + ")");
    Handle service(CreateServiceW(manager.get(), service_name(options.instance).c_str(), display.c_str(),
                                  SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                  options.boot ? SERVICE_AUTO_START : SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                  command.c_str(), nullptr, nullptr, L"Tcpip\0\0", account(options.instance).c_str(),
                                  nullptr));
    if (!service) {
        const DWORD err = GetLastError();
        std::cerr << "erreur : création du service impossible : "
                  << (err == ERROR_SERVICE_EXISTS ? std::string("déjà installé") : error_text(err)) << '\n';
        return kExitRuntime;
    }

    std::wstring description = L"Relais TCP clair / TLS 1.3 / mTLS";
    SERVICE_DESCRIPTIONW desc{description.data()};
    ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &desc);

    // Compte virtuel : identité propre au service, sans privilège particulier.
    SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
    ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_SERVICE_SID_INFO, &sid);
    wchar_t privileges[] = L"SeChangeNotifyPrivilege\0";
    SERVICE_REQUIRED_PRIVILEGES_INFOW required{privileges};
    ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &required);

    // Arrêt du système : le service reçoit PRESHUTDOWN et dispose du délai de drain.
    SERVICE_PRESHUTDOWN_INFO preshutdown{
        static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(options.shutdown_timeout).count() +
                           15000)};
    ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_PRESHUTDOWN_INFO, &preshutdown);

    // Relance automatique en cas d'arrêt anormal (3 fois, à 2 s d'intervalle, compteur remis à zéro chaque jour).
    SC_ACTION actions[3] = {{SC_ACTION_RESTART, 2000}, {SC_ACTION_RESTART, 2000}, {SC_ACTION_RESTART, 2000}};
    SERVICE_FAILURE_ACTIONSW failure{};
    failure.dwResetPeriod = 86400;
    failure.cActions = 3;
    failure.lpsaActions = actions;
    ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failure);

    // Journaux par défaut d'un service (logging.output: stderr) : répertoire accessible au compte du service.
    std::error_code ec;
    const auto logs = program_data() / "logs";
    fs::create_directories(logs, ec);
    if (ec || !grant_modify(logs, account(options.instance))) {
        std::cerr << "avertissement : droits du service sur " << logs.string() << " non appliqués\n";
    }

    std::cout << "service tlsrelay-" << options.instance << " installé (configuration " << options.config.string()
              << (options.boot ? ", démarrage au boot" : ", démarrage manuel") << ", compte NT SERVICE\\tlsrelay-"
              << options.instance << ")\n"
              << "ce compte doit pouvoir lire la configuration, la liste blanche et la PKI\n"
              << "démarrage : tlsrelay start --instance " << options.instance << '\n';
    return kExitOk;
}

int service_uninstall(const std::string& instance) {
    Handle service = open_service(instance, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!service) return kExitRuntime;
    if (auto status = query(service.get()); status && status->dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS ignored{};
        ControlService(service.get(), SERVICE_CONTROL_STOP, &ignored);
        wait_while(service.get(), SERVICE_STOP_PENDING, std::chrono::minutes(2));
    }
    if (!DeleteService(service.get())) {
        std::cerr << "erreur : suppression du service impossible : " << error_text(GetLastError()) << '\n';
        return kExitRuntime;
    }
    std::cout << "service tlsrelay-" << instance << " désinstallé\n";
    return kExitOk;
}

int service_start(const std::string& instance, Duration timeout) {
    Handle service = open_service(instance, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) return kExitRuntime;
    if (!StartServiceW(service.get(), 0, nullptr)) {
        const DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::cerr << "erreur : démarrage impossible : " << error_text(err) << '\n';
            return kExitRuntime;
        }
    }
    const auto status = wait_while(service.get(), SERVICE_START_PENDING, timeout);
    if (!status || status->dwCurrentState != SERVICE_RUNNING) {
        std::cerr << "erreur : le service n'a pas démarré";
        if (status && status->dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR) {
            std::cerr << " (code de sortie " << status->dwServiceSpecificExitCode << ", voir le journal)";
        } else if (status && status->dwWin32ExitCode != NO_ERROR) {
            std::cerr << " (" << error_text(status->dwWin32ExitCode) << ")";
        }
        std::cerr << '\n';
        return kExitRuntime;
    }
    return kExitOk;
}

void service_wait_stopped(const std::string& instance, Duration timeout) {
    Handle service = open_service(instance, SERVICE_QUERY_STATUS, false);
    if (!service) return;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto status = query(service.get());
        if (!status || status->dwCurrentState == SERVICE_STOPPED) return;
        std::this_thread::sleep_for(100ms);
    }
}

int service_force_kill(const std::string& instance) {
    Handle service = open_service(instance, SERVICE_QUERY_STATUS);
    if (!service) return kExitRuntime;
    const auto status = query(service.get());
    if (!status || status->dwProcessId == 0) {
        std::cerr << "erreur : processus du service introuvable\n";
        return kExitRuntime;
    }
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, status->dwProcessId);
    if (!process || !TerminateProcess(process, 1)) {
        std::cerr << "erreur : arrêt forcé impossible : " << error_text(GetLastError()) << '\n';
        if (process) CloseHandle(process);
        return kExitRuntime;
    }
    CloseHandle(process);
    return kExitOk;
}

// ---------------------------------------------------------------------------
// Processus du service

namespace {

struct Dispatch {
    std::wstring name;
    std::function<int(ServiceControl&)> run;
    SERVICE_STATUS_HANDLE handle = nullptr;
    std::mutex mutex;
    SERVICE_STATUS status{};
    std::function<void()> stop;  // protégé par mutex
    bool stop_requested = false;
};

Dispatch* g_dispatch = nullptr;

void report(DWORD state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0) {
    std::lock_guard lock(g_dispatch->mutex);
    auto& s = g_dispatch->status;
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN : 0;
    if (exit_code == NO_ERROR) {
        s.dwWin32ExitCode = NO_ERROR;
        s.dwServiceSpecificExitCode = 0;
    } else {
        s.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        s.dwServiceSpecificExitCode = exit_code;
    }
    s.dwWaitHint = wait_hint;
    s.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : s.dwCheckPoint + 1;
    SetServiceStatus(g_dispatch->handle, &s);
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_PRESHUTDOWN: {
            report(SERVICE_STOP_PENDING, NO_ERROR, 60000);
            std::function<void()> stop;
            {
                std::lock_guard lock(g_dispatch->mutex);
                g_dispatch->stop_requested = true;
                stop = g_dispatch->stop;
            }
            if (stop) stop();
            return NO_ERROR;
        }
        case SERVICE_CONTROL_INTERROGATE: return NO_ERROR;
        default: return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

class WindowsControl final : public ServiceControl {
public:
    void ready(std::function<void()> request_stop) override {
        bool early = false;
        {
            std::lock_guard lock(g_dispatch->mutex);
            g_dispatch->stop = request_stop;
            early = g_dispatch->stop_requested;
        }
        report(SERVICE_RUNNING);
        if (early) request_stop();  // arrêt demandé pendant le démarrage
    }
};

void WINAPI service_main(DWORD, LPWSTR*) {
    g_dispatch->handle = RegisterServiceCtrlHandlerExW(g_dispatch->name.c_str(), control_handler, nullptr);
    if (!g_dispatch->handle) return;
    report(SERVICE_START_PENDING, NO_ERROR, 30000);
    WindowsControl control;
    int code = 1;
    try {
        code = g_dispatch->run(control);
    } catch (...) {
        code = 1;
    }
    report(SERVICE_STOPPED, static_cast<DWORD>(code));
}

}  // namespace

int service_dispatch(const std::string& instance, std::function<int(ServiceControl&)> run) {
    Dispatch dispatch;
    dispatch.name = service_name(instance);
    dispatch.run = std::move(run);
    g_dispatch = &dispatch;
    SERVICE_TABLE_ENTRYW table[] = {{dispatch.name.data(), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        const DWORD err = GetLastError();
        std::cerr << "erreur : service-run est réservé au gestionnaire de services ("
                  << (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT ? std::string("utiliser « tlsrelay run »")
                                                                     : error_text(err))
                  << ")\n";
        return kExitRuntime;
    }
    return kExitOk;
}

}  // namespace tlsrelay::app
