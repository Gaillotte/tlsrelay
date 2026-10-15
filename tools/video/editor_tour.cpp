// Visite de l'éditeur tlsrelay-admin pour la vidéo de démonstration
// (tools/video/make-video.sh) : ouvre les fichiers produits par tools/demo.sh
// et enregistre une image de chaque écran, sans affichage (plateforme
// « offscreen »). Cible hors de la compilation par défaut : tlsrelay-admin-tour.
// Usage : tlsrelay-admin-tour <répertoire de tools/demo.sh (DEMO_DIR)> <répertoire des images>

#include "diff_dialog.hpp"
#include "document.hpp"
#include "export_dialog.hpp"
#include "main_window.hpp"
#include "pki_panel.hpp"
#include "sign_dialog.hpp"
#include "whitelist_editor.hpp"

#include <QApplication>
#include <QComboBox>
#include <QDeadlineTimer>
#include <QDialog>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>

#include <filesystem>
#include <functional>
#include <iostream>

using namespace tlsrelay::admin;
namespace fs = std::filesystem;

namespace {

fs::path out_dir;
int shots = 0;

void settle() {
    for (int i = 0; i < 5; ++i) QApplication::processEvents();
}

void shoot(QWidget* w, const std::string& name) {
    settle();
    const auto file = out_dir / (name + ".png");
    if (!w->grab().save(QString::fromStdString(file.string()))) {
        std::cerr << "échec : " << file << '\n';
        std::exit(1);
    }
    ++shots;
    std::cout << file.string() << '\n';
}

// Capture la prochaine fenêtre modale puis la ferme sans rien faire.
void shoot_next_modal(const std::string& name) {
    auto* timer = new QTimer;
    QObject::connect(timer, &QTimer::timeout, timer, [timer, name] {
        auto* d = qobject_cast<QDialog*>(QApplication::activeModalWidget());
        if (!d) return;
        timer->stop();
        timer->deleteLater();
        shoot(d, name);
        d->reject();
    });
    timer->start(50);
}

QPushButton* button(QWidget* parent, const QString& text) {
    for (auto* b : parent->findChildren<QPushButton*>()) {
        if (b->text() == text) return b;
    }
    std::cerr << "bouton absent : " << text.toStdString() << '\n';
    std::exit(1);
}

QTabWidget* tabs_with(QWidget* parent, int count) {
    for (auto* t : parent->findChildren<QTabWidget*>()) {
        if (t->count() == count) return t;
    }
    std::exit(1);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage : tlsrelay-admin-tour <répertoire de la démonstration> <répertoire des images>\n";
        return 2;
    }
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    const fs::path demo = argv[1];
    out_dir = argv[2];
    fs::create_directories(out_dir);

    MainWindow window;
    window.report = [](const QString& m) { std::cerr << m.toStdString() << '\n'; };
    window.pki_panel()->report = window.report;
    window.resize(1240, 700);
    window.show();
    auto* tabs = tabs_with(&window, 3);

    // 1. Configuration du serveur de la démonstration.
    if (!window.open_file(demo / "server.yaml")) return 1;
    shoot(&window, "01-configuration");

    // 2. Saisie invalide : champ encadré, erreur listée (règles du service).
    const auto tls_listen = window.config_form()->value("ports.tls.listen");
    const auto idle = window.config_form()->value("limits.idle_timeout");
    window.config_form()->set_value("ports.tls.listen", "127.0.0.1:99999");
    window.config_form()->set_value("limits.idle_timeout", "cinq minutes");
    shoot(&window, "02-errors");
    window.config_form()->set_value("ports.tls.listen", tls_listen);
    window.config_form()->set_value("limits.idle_timeout", idle);

    // 3. Liste blanche, avec un pair ajouté.
    tabs->setCurrentIndex(1);
    window.whitelist_editor()->add_peer();
    auto* table = window.whitelist_editor()->table();
    table->item(1, WhitelistEditor::name)->setText("agence-lyon");
    table->item(1, WhitelistEditor::ip)->setText("192.0.2.10");
    shoot(&window, "03-whitelist");

    // 4. Aperçu des différences avant l'enregistrement.
    window.config_form()->set_value("limits.max_channels", "2000");
    window.confirm_save = [](const std::vector<FileChange>& changes) {
        DiffDialog dialog(changes);
        dialog.resize(1100, 640);
        dialog.show();
        shoot(&dialog, "04-diff");
        return false;  // rien n'est écrit
    };
    window.save();

    // 5. Export d'un paquet de déploiement pour Windows.
    if (const auto request = window.export_request()) {
        ExportDialog dialog(*request);
        dialog.findChild<QLineEdit*>("sortie")->setText("C:/deploiement");
        dialog.findChild<QComboBox*>("plateforme")->setCurrentIndex(1);
        dialog.findChild<QLineEdit*>("kit")->setText(QString::fromStdString((demo / "kit-server-v2").string()));
        dialog.findChild<QLineEdit*>("crl")->setText(QString::fromStdString((demo / "crl.pem").string()));
        dialog.resize(900, 420);
        dialog.show();
        shoot(&dialog, "05-export");
    }

    // 6. Module PKI : l'AC de la démonstration (inventaire, révocation, CRL).
    tabs->setCurrentIndex(2);
    auto* panel = window.pki_panel();
    if (!panel->open_authority(demo / "ca")) return 1;
    shoot(&window, "06-pki-inventory");
    tabs_with(panel, 2)->setCurrentIndex(1);
    shoot(&window, "07-pki-audit");
    tabs_with(panel, 2)->setCurrentIndex(0);

    // 7. Dialogue de signature : la demande est examinée dès qu'elle est choisie.
    {
        SignDialog dialog(false, {}, tlsrelay::pki::Role::server);
        dialog.set_csr(QString::fromStdString((demo / "pki-server" / "v2" / "request.csr").string()));
        dialog.set_sans("relay.demo");
        dialog.resize(800, 460);
        dialog.show();
        shoot(&dialog, "08-sign");
    }

    // 8. Révocation et assistant de changement de racine.
    for (int r = 0; r < panel->inventory()->rowCount(); ++r) {
        if (panel->inventory()->item(r, PkiPanel::status_column)->text() == "valide") {
            panel->inventory()->selectRow(r);
            break;
        }
    }
    shoot_next_modal("09-revoke");
    button(panel, "Révoquer…")->click();
    shoot_next_modal("10-root-change");
    button(panel, "Changement de racine…")->click();

    std::cout << shots << " image(s)\n";
    return shots == 10 ? 0 : 1;
}
