// tlsrelay-admin : éditeur de configuration et de PKI de tlsrelay (livraison 1.1).
// Usage : tlsrelay-admin [configuration.yaml]

#include "document.hpp"
#include "main_window.hpp"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("tlsrelay-admin");
    QApplication::setOrganizationName("tlsrelay");
    tlsrelay::admin::MainWindow window;
    const auto args = QApplication::arguments();
    if (args.size() > 1) window.open_file(tlsrelay::admin::to_path(args.at(1)));
    window.show();
    return QApplication::exec();
}
