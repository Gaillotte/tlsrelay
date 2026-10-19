#pragma once

// Integration with the system service manager (SPEC §10):
// systemd (template unit tlsrelay@.service) on Linux, Service Control
// Manager (service tlsrelay-<instance>) on Windows.

#include "tlsrelay/units.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace tlsrelay::app {

// Default configuration file of an instance:
// /etc/tlsrelay/<instance>.yaml or %ProgramData%\tlsrelay\<instance>.yaml.
std::filesystem::path default_config_path(const std::string& instance);

struct InstallOptions {
    std::string instance;
    std::filesystem::path config;  // absolute path, configuration already validated
    bool boot = false;             // start automatically with the system
    Duration shutdown_timeout{};   // limits.shutdown_timeout from the configuration
};

// Each function prints what it does and returns an exit code.
int service_install(const InstallOptions& options);
int service_uninstall(const std::string& instance);
bool service_installed(const std::string& instance);
// Starts the installed service (without waiting for the administration channel).
int service_start(const std::string& instance, Duration timeout);
// Waits until the service manager sees the instance as stopped.
void service_wait_stopped(const std::string& instance, Duration timeout);
// Forced stop through the service manager (if the channel no longer responds).
int service_force_kill(const std::string& instance);

// Link between the running instance and the service manager.
class ServiceControl {
public:
    virtual ~ServiceControl() = default;
    // Ports open: the service is running. request_stop triggers the graceful stop.
    virtual void ready(std::function<void()> request_stop) = 0;
};

#ifdef _WIN32
// Log of a service whose configuration writes to stderr:
// %ProgramData%\tlsrelay\logs\<instance>.log.
std::filesystem::path default_service_log(const std::string& instance);

// Entry point of the process launched by the Windows service manager
// (internal command service-run). run executes the instance until it stops.
int service_dispatch(const std::string& instance, std::function<int(ServiceControl&)> run);
#endif

}  // namespace tlsrelay::app
