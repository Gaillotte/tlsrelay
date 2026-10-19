// tlsrelay-admin: configuration and PKI editor for tlsrelay (release 1.1).
// Usage:
//   tlsrelay-admin [configuration.yaml]
//   tlsrelay-admin --check configuration.yaml
//     Checks a configuration (and its whitelist, in server mode) with
//     the service rules, without a window. Exit code: 0 valid,
//     1 invalid, 2 unreadable file. Messages go to standard error
//     and, when given, to the --report file.

#include "document.hpp"
#include "main_window.hpp"

#include "tlsrelay/config.hpp"
#include "tlsrelay/whitelist.hpp"

#include <QApplication>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string_view>

namespace {

int check(const std::filesystem::path& path, const std::filesystem::path& report_path) {
    std::ostringstream report;
    int code = 0;
    const auto text = tlsrelay::admin::read_text(path);
    if (!text) {
        report << path.string() << ": unreadable file\n";
        code = 2;
    } else {
        const auto config = tlsrelay::load_config_string(*text);
        for (const auto& e : config.errors) report << "error: " << e.path << ": " << e.message << '\n';
        for (const auto& w : config.warnings) report << "warning: " << w.path << ": " << w.message << '\n';
        if (!config.config) code = 1;
        if (config.config && config.config->whitelist) {
            const auto wl_path = tlsrelay::admin::resolve_from(path, config.config->whitelist->file);
            const auto wl = tlsrelay::whitelist::Whitelist::load_file(wl_path);
            for (const auto& e : wl.errors) report << "error: " << e.path << ": " << e.message << '\n';
            for (const auto& w : wl.warnings) report << "warning: " << w.path << ": " << w.message << '\n';
            if (!wl.whitelist) code = 1;
        }
        report << path.string() << (code == 0 ? ": valid\n" : ": invalid\n");
    }
    std::cerr << report.str();
    if (!report_path.empty()) std::ofstream(report_path, std::ios::binary) << report.str();
    return code;
}

}  // namespace

int main(int argc, char* argv[]) {
    // The Qt application is created even for --check: an installation that
    // lacks DLLs or the Qt platform plugin fails here too.
    // Without a display (Linux server, SSH session), --check uses the "offscreen"
    // platform: the check opens no window.
    const bool check_mode = argc >= 3 && std::string_view(argv[1]) == "--check";
    if (check_mode && qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM") && qEnvironmentVariableIsEmpty("DISPLAY") &&
        qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY")) {
#ifndef _WIN32
        qputenv("QT_QPA_PLATFORM", "offscreen");
#endif
    }
    QApplication app(argc, argv);
    QApplication::setApplicationName("tlsrelay-admin");
    QApplication::setOrganizationName("tlsrelay");
    const auto args = QApplication::arguments();
    if (args.size() >= 3 && args.at(1) == "--check") {
        const auto report = args.size() >= 5 && args.at(3) == "--report" ? args.at(4) : QString();
        return check(tlsrelay::admin::to_path(args.at(2)), tlsrelay::admin::to_path(report));
    }
    tlsrelay::admin::MainWindow window;
    if (args.size() > 1) window.open_file(tlsrelay::admin::to_path(args.at(1)));
    window.show();
    return QApplication::exec();
}
