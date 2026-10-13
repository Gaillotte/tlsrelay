// tlsrelay-admin : éditeur de configuration et de PKI de tlsrelay (livraison 1.1).
// Usage :
//   tlsrelay-admin [configuration.yaml]
//   tlsrelay-admin --check configuration.yaml
//     Contrôle une configuration (et sa liste blanche, en mode serveur) avec
//     les règles du service, sans fenêtre. Code de sortie : 0 valide,
//     1 invalide, 2 fichier illisible. Les messages vont sur la sortie
//     d'erreur et, s'il est donné, dans le fichier --report.

#include "document.hpp"
#include "main_window.hpp"

#include "tlsrelay/config.hpp"
#include "tlsrelay/whitelist.hpp"

#include <QApplication>

#include <fstream>
#include <iostream>
#include <sstream>

namespace {

int check(const std::filesystem::path& path, const std::filesystem::path& report_path) {
    std::ostringstream report;
    int code = 0;
    const auto text = tlsrelay::admin::read_text(path);
    if (!text) {
        report << path.string() << " : fichier illisible\n";
        code = 2;
    } else {
        const auto config = tlsrelay::load_config_string(*text);
        for (const auto& e : config.errors) report << "erreur : " << e.path << " : " << e.message << '\n';
        for (const auto& w : config.warnings) report << "avertissement : " << w.path << " : " << w.message << '\n';
        if (!config.config) code = 1;
        if (config.config && config.config->whitelist) {
            const auto wl_path = tlsrelay::admin::resolve_from(path, config.config->whitelist->file);
            const auto wl = tlsrelay::whitelist::Whitelist::load_file(wl_path);
            for (const auto& e : wl.errors) report << "erreur : " << e.path << " : " << e.message << '\n';
            for (const auto& w : wl.warnings) report << "avertissement : " << w.path << " : " << w.message << '\n';
            if (!wl.whitelist) code = 1;
        }
        report << path.string() << (code == 0 ? " : valide\n" : " : invalide\n");
    }
    std::cerr << report.str();
    if (!report_path.empty()) std::ofstream(report_path, std::ios::binary) << report.str();
    return code;
}

}  // namespace

int main(int argc, char* argv[]) {
    // L'application Qt est créée même pour --check : une installation à qui
    // manquent des DLL ou le module de plateforme de Qt échoue ici aussi.
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
