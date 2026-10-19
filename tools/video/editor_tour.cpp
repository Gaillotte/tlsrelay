// Tour of the tlsrelay-admin editor for the demonstration video
// (tools/video/make-video.sh): opens the files produced by tools/demo.sh
// and saves an image of each screen, without a display ("offscreen"
// platform). Target excluded from the default build: tlsrelay-admin-tour.
// Usage: tlsrelay-admin-tour <tools/demo.sh directory (DEMO_DIR)> <image directory>

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
        std::cerr << "failed: " << file << '\n';
        std::exit(1);
    }
    ++shots;
    std::cout << file.string() << '\n';
}

// Captures the next modal window, then closes it without doing anything.
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
    std::cerr << "missing button: " << text.toStdString() << '\n';
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
        std::cerr << "usage: tlsrelay-admin-tour <demonstration directory> <image directory>\n";
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

    // 1. Configuration of the demonstration server.
    if (!window.open_file(demo / "server.yaml")) return 1;
    shoot(&window, "01-configuration");

    // 2. Invalid input: field framed, error listed (service rules).
    const auto tls_listen = window.config_form()->value("ports.tls.listen");
    const auto idle = window.config_form()->value("limits.idle_timeout");
    window.config_form()->set_value("ports.tls.listen", "127.0.0.1:99999");
    window.config_form()->set_value("limits.idle_timeout", "five minutes");
    shoot(&window, "02-errors");
    window.config_form()->set_value("ports.tls.listen", tls_listen);
    window.config_form()->set_value("limits.idle_timeout", idle);

    // 3. Whitelist, with an added peer.
    tabs->setCurrentIndex(1);
    window.whitelist_editor()->add_peer();
    auto* table = window.whitelist_editor()->table();
    table->item(1, WhitelistEditor::name)->setText("branch-lyon");
    table->item(1, WhitelistEditor::ip)->setText("192.0.2.10");
    shoot(&window, "03-whitelist");

    // 4. Diff preview before saving.
    window.config_form()->set_value("limits.max_channels", "2000");
    window.confirm_save = [](const std::vector<FileChange>& changes) {
        DiffDialog dialog(changes);
        dialog.resize(1100, 640);
        dialog.show();
        shoot(&dialog, "04-diff");
        return false;  // nothing is written
    };
    window.save();

    // 5. Export of a deployment package for Windows.
    if (const auto request = window.export_request()) {
        ExportDialog dialog(*request);
        dialog.findChild<QLineEdit*>("output")->setText("C:/deployment");
        dialog.findChild<QComboBox*>("platform")->setCurrentIndex(1);
        dialog.findChild<QLineEdit*>("kit")->setText(QString::fromStdString((demo / "kit-server-v2").string()));
        dialog.findChild<QLineEdit*>("crl")->setText(QString::fromStdString((demo / "crl.pem").string()));
        dialog.resize(900, 420);
        dialog.show();
        shoot(&dialog, "05-export");
    }

    // 6. PKI module: the demonstration CA (inventory, revocation, CRL).
    tabs->setCurrentIndex(2);
    auto* panel = window.pki_panel();
    if (!panel->open_authority(demo / "ca")) return 1;
    shoot(&window, "06-pki-inventory");
    tabs_with(panel, 2)->setCurrentIndex(1);
    shoot(&window, "07-pki-audit");
    tabs_with(panel, 2)->setCurrentIndex(0);

    // 7. Signing dialog: the request is inspected as soon as it is chosen.
    {
        SignDialog dialog(false, {}, tlsrelay::pki::Role::server);
        dialog.set_csr(QString::fromStdString((demo / "pki-server" / "v2" / "request.csr").string()));
        dialog.set_sans("relay.demo");
        dialog.resize(800, 460);
        dialog.show();
        shoot(&dialog, "08-sign");
    }

    // 8. Revocation and root change wizard.
    for (int r = 0; r < panel->inventory()->rowCount(); ++r) {
        if (panel->inventory()->item(r, PkiPanel::status_column)->text() == "valid") {
            panel->inventory()->selectRow(r);
            break;
        }
    }
    shoot_next_modal("09-revoke");
    button(panel, "Revoke…")->click();
    shoot_next_modal("10-root-change");
    button(panel, "Root change…")->click();

    std::cout << shots << " image(s)\n";
    return shots == 10 ? 0 : 1;
}
