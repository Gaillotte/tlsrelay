// Tests de l'éditeur tlsrelay-admin (Qt Test, plateforme « offscreen »).

#include "config_form.hpp"
#include "deployment.hpp"
#include "diff_dialog.hpp"
#include "document.hpp"
#include "main_window.hpp"
#include "whitelist_editor.hpp"

#include <QListWidget>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QtTest>

#include <fstream>

using namespace tlsrelay;
using namespace tlsrelay::admin;

namespace {

std::string read(const std::filesystem::path& p) { return read_text(p).value_or(""); }

void write(const std::filesystem::path& p, const std::string& text) {
    std::ofstream(p, std::ios::binary | std::ios::trunc) << text;
}

std::string issues_text(const std::vector<Issue>& issues) {
    std::string s;
    for (const auto& i : issues) s += i.path + " : " + i.message + "\n";
    return s;
}

const char* kServer = R"(
mode: server
instance: agence
credentials: { pki_root: /etc/tlsrelay/agence/pki }
whitelist: { file: whitelist.yaml }
destination: { address: 10.0.0.5, port: 8080 }
ports:
  mtls: { listen: "0.0.0.0:9003" }
)";

}  // namespace

class AdminTest : public QObject {
    Q_OBJECT

private slots:
    void form_round_trips_examples();
    void validation_matches_service();
    void invalid_fields_are_marked();
    void fields_without_object_are_hidden_unless_filled();
    void whitelist_editor_round_trip_and_marks();
    void open_edit_save_with_preview_and_backup();
    void save_refused_while_invalid();
    void new_document_is_saved_normalized();
    void export_package_for_linux_and_windows();
    void diff_preview_lists_changes();
};

void AdminTest::form_round_trips_examples() {
    for (const char* name : {"client.yaml", "server.yaml"}) {
        const auto text = read(std::filesystem::path(TLSRELAY_EXAMPLES_DIR) / name);
        const auto original = load_config_string(text);
        QVERIFY2(original.config.has_value(), name);
        ConfigForm form;
        const auto ignored = form.load_yaml(text);
        QVERIFY2(ignored.empty(), ignored.empty() ? "" : ignored.front().c_str());
        const auto result = form.validate();
        QVERIFY2(result.config.has_value(), issues_text(result.errors).c_str());
        QVERIFY(*result.config == *original.config);
    }
}

// Parité éditeur/service : un fichier chargé dans le formulaire produit les
// mêmes erreurs (chemins et messages) que lu directement par le service.
void AdminTest::validation_matches_service() {
    const std::vector<std::string> corpus = {
        kServer,
        "mode: client\n",
        "mode: server\nports: { plain: { listen: \"0.0.0.0:9001\" } }\n",
        "mode: bridge\n",
        "mode: client\ninstance: \"nom invalide!\"\nports: { tls: { listen: \"127.0.0.1:7002\" } }\n",
        "mode: client\nports: { tls: { listen: \"127.0.0.1:7002\", upstream: \"r:9002\" } }\n",
        "mode: client\nlimits: { idle_timeout: 5 minutes, session_jitter: 80%, max_channels: -1 }\n"
        "ports: { plain: { listen: \"127.0.0.1:7001\", upstream: \"r:9001\", server_name: x } }\n",
        "mode: server\ndestination: { address: d, port: 70000, dial_retries: 0 }\nwhitelist: { file: w.yaml }\n"
        "ports: { plain: { listen: \"0.0.0.0:9001\", upstream: \"r:1\" }, tls: { listen: \"0.0.0.0:9001\" } }\n",
        "mode: server\nsource_address: 1.2.3.4\ndestination: { address: d, port: 1 }\nwhitelist: { file: w }\n"
        "ports: { plain: { listen: \"host:9001\" } }\nlogging: { level: verbeux, output: syslog }\n",
        "mode: client\ncredentials: { watch: peut-être }\nadmin: { enabled: oui, endpoint: \"\" }\n"
        "ports: { mtls: { listen: \"[::1]:7003\", upstream: \"[2001:db8::1]:9003\", server_name: relais } }\n",
    };
    for (const auto& text : corpus) {
        const auto direct = load_config_string(text);
        ConfigForm form;
        form.load_yaml(text);
        const auto edited = form.validate();
        QCOMPARE(QString::fromStdString(issues_text(edited.errors)), QString::fromStdString(issues_text(direct.errors)));
        QCOMPARE(edited.config.has_value(), direct.config.has_value());
        if (direct.config) QVERIFY(*edited.config == *direct.config);
    }
}

void AdminTest::invalid_fields_are_marked() {
    ConfigForm form;
    form.load_yaml(kServer);
    QVERIFY(form.validate().config.has_value());
    form.set_value("limits.idle_timeout", "cinq minutes");
    form.set_value("destination.port", "99999");
    const auto result = form.validate();
    QVERIFY(!result.config);
    auto* idle = form.widget_for("limits.idle_timeout");
    QVERIFY(idle->property("invalid").toBool());
    QVERIFY(idle->toolTip().contains("durée invalide"));
    QVERIFY(form.widget_for("destination.port")->property("invalid").toBool());
    // Une erreur de section désigne la section.
    QCOMPARE(form.widget_for("ports.tls"), form.widget_for("ports.tls.inconnu"));
    form.set_value("limits.idle_timeout", "");
    form.set_value("destination.port", "8080");
    QVERIFY(form.validate().config.has_value());
    QVERIFY(!idle->property("invalid").toBool());
}

void AdminTest::fields_without_object_are_hidden_unless_filled() {
    ConfigForm form;
    form.load_yaml(kServer);
    QVERIFY(form.is_shown("destination.address"));
    QVERIFY(!form.is_shown("ports.mtls.upstream"));
    QVERIFY(!form.is_shown("source_address"));
    form.set_value("mode", "client");
    QVERIFY(form.is_shown("ports.mtls.upstream"));
    QVERIFY(form.is_shown("destination.address"));  // rempli : reste visible pour être corrigé
    const auto result = form.validate();
    QVERIFY(QString::fromStdString(issues_text(result.errors)).contains("destination : sans objet en mode client"));
    QVERIFY(!form.is_shown("ports.plain.server_name"));
}

void AdminTest::whitelist_editor_round_trip_and_marks() {
    WhitelistEditor editor;
    const std::string text = "peers:\n"
                             "  - { name: lyon, ip: 192.0.2.10, ports: [mtls], subject: \"CN=lyon,O=E\" }\n"
                             "  - { name: nantes, ip: 198.51.100.0/24 }\n"
                             "  - { name: x, ip: 203.0.113.1, ports: [ftp], couleur: bleu }\n";
    const auto ignored = editor.load_yaml(text);
    QCOMPARE(ignored.size(), size_t(3));  // port ftp, liste de ports vide, clé couleur
    QCOMPARE(editor.table()->rowCount(), 3);
    const auto peers = editor.peers();
    QVERIFY(peers[0].ports && peers[0].ports->count(PortKind::mtls));
    QVERIFY(!peers[1].ports);
    QVERIFY(editor.validate().whitelist != nullptr);

    // Erreurs : nom en double, IP invalide, mtls sans sujet.
    editor.table()->item(1, WhitelistEditor::name)->setText("lyon");
    editor.table()->item(2, WhitelistEditor::ip)->setText("300.0.0.1");
    editor.table()->item(2, WhitelistEditor::mtls)->setCheckState(Qt::Checked);
    const auto result = editor.validate();
    QVERIFY(!result.whitelist);
    QVERIFY(editor.table()->item(1, WhitelistEditor::name)->data(Qt::UserRole).toBool());
    QVERIFY(editor.table()->item(2, WhitelistEditor::ip)->data(Qt::UserRole).toBool());
    QVERIFY(editor.table()->item(2, WhitelistEditor::subject)->data(Qt::UserRole).toBool());
    QVERIFY(!editor.table()->item(0, WhitelistEditor::name)->data(Qt::UserRole).toBool());

    editor.add_peer();
    QCOMPARE(editor.table()->rowCount(), 4);
    editor.table()->setCurrentCell(3, 0);
    editor.remove_selected();
    editor.table()->setCurrentCell(0, 0);
    editor.move_selected(1);
    QCOMPARE(editor.peers()[1].subject, std::string("CN=lyon,O=E"));
}

void AdminTest::open_edit_save_with_preview_and_backup() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    write(dir / "agence.yaml", std::string("# commentaire d'origine\n") + kServer);
    write(dir / "whitelist.yaml", "peers:\n  - { name: lyon, ip: 192.0.2.10, ports: [mtls], subject: \"CN=lyon\" }\n");

    MainWindow window;
    std::vector<FileChange> shown;
    window.confirm_save = [&](const std::vector<FileChange>& changes) {
        shown = changes;
        return true;
    };
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    QVERIFY(window.open_file(dir / "agence.yaml"));
    QCOMPARE(window.error_count(), 0);
    QVERIFY(!window.is_modified());
    QCOMPARE(window.whitelist_editor()->table()->rowCount(), 1);

    window.config_form()->set_value("limits.max_channels", "200");
    window.whitelist_editor()->add_peer();
    auto* table = window.whitelist_editor()->table();
    table->item(1, WhitelistEditor::name)->setText("nantes");
    table->item(1, WhitelistEditor::ip)->setText("198.51.100.7");
    QVERIFY(window.is_modified());
    QCOMPARE(window.error_count(), 0);
    QVERIFY(window.save());
    QVERIFY2(reports.isEmpty(), qPrintable(reports.join("\n")));
    QCOMPARE(shown.size(), size_t(2));
    QVERIFY(shown[0].changed() && shown[1].changed());

    // Fichiers réécrits, originaux en .bak, relus à l'identique par le service.
    QVERIFY(read(dir / "agence.yaml.bak").find("# commentaire d'origine") != std::string::npos);
    QVERIFY(std::filesystem::exists(dir / "whitelist.yaml.bak"));
    const auto saved = load_config_file(dir / "agence.yaml");
    QVERIFY2(saved.config.has_value(), issues_text(saved.errors).c_str());
    QCOMPARE(saved.config->limits.max_channels, 200u);
    const auto wl = whitelist::Whitelist::load_file(dir / "whitelist.yaml");
    QVERIFY(wl.whitelist);
    QCOMPARE(wl.whitelist->peers().size(), size_t(2));
    QVERIFY(!window.is_modified());

    // Second enregistrement sans modification : rien à confirmer, rien d'écrit.
    shown.clear();
    QVERIFY(window.save());
    QVERIFY(shown.empty());

    // Refus de l'aperçu : rien n'est écrit.
    window.config_form()->set_value("limits.max_channels", "300");
    window.confirm_save = [](const std::vector<FileChange>&) { return false; };
    QVERIFY(!window.save());
    QCOMPARE(load_config_file(dir / "agence.yaml").config->limits.max_channels, 200u);
}

void AdminTest::save_refused_while_invalid() {
    QTemporaryDir tmp;
    MainWindow window;
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    window.confirm_save = [](const std::vector<FileChange>&) { return true; };
    window.new_document(Mode::server);
    QVERIFY(window.error_count() > 0);  // ports, destination, liste blanche manquants
    QVERIFY(window.issues()->count() >= window.error_count());
    const auto path = to_path(tmp.path()) / "x.yaml";
    QVERIFY(!window.save_to(path));
    QCOMPARE(reports.size(), 1);
    QVERIFY(!std::filesystem::exists(path));
}

void AdminTest::new_document_is_saved_normalized() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    MainWindow window;
    window.confirm_save = [](const std::vector<FileChange>&) { return true; };
    window.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    window.new_document(Mode::client);
    auto* form = window.config_form();
    form->set_value("instance", "poste");
    form->set_port_enabled(PortKind::tls, true);
    form->set_value("ports.tls.listen", "127.0.0.1:7002");
    form->set_value("ports.tls.upstream", "relais.exemple:9002");
    form->set_value("ports.tls.server_name", "relais.exemple");
    form->set_value("credentials.pki_root", "/etc/tlsrelay/poste/pki");
    QCOMPARE(window.error_count(), 0);
    QVERIFY(window.save_to(dir / "poste.yaml"));
    const auto text = read(dir / "poste.yaml");
    QVERIFY(text.rfind("# Écrit par tlsrelay-admin", 0) == 0);
    QVERIFY(text.find("limits") == std::string::npos);  // valeurs par défaut omises
    QVERIFY(!std::filesystem::exists(dir / "poste.yaml.bak"));
    QVERIFY(load_config_string(text).config.has_value());
}

void AdminTest::export_package_for_linux_and_windows() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    MainWindow window;
    window.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    write(dir / "agence.yaml", std::string(kServer).replace(std::string(kServer).find("whitelist.yaml"), 14,
                                                            "/etc/tlsrelay/agence/whitelist.yaml"));
    QVERIFY(window.open_file(dir / "agence.yaml"));
    window.whitelist_editor()->add_peer();
    auto* table = window.whitelist_editor()->table();
    table->item(0, WhitelistEditor::name)->setText("lyon");
    table->item(0, WhitelistEditor::ip)->setText("192.0.2.10");
    auto request = window.export_request();
    QVERIFY(request.has_value());

    std::filesystem::create_directories(dir / "kit");
    for (const char* f : {"cert.pem", "chain.pem", "trust-roots.pem", "trust-issuer.pem"}) write(dir / "kit" / f, "PEM\n");
    write(dir / "crl.pem", "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n");

    request->out_dir = dir / "linux";
    request->kit_dir = dir / "kit";
    request->crl_file = dir / "crl.pem";
    const auto linux_dir = window.export_package(*request);
    QVERIFY(linux_dir.has_value());
    QCOMPARE(*linux_dir, dir / "linux" / "agence");
    for (const char* f : {"agence.yaml", "whitelist.yaml", "kit/cert.pem", "crl.pem", "install.sh", "LISEZMOI.txt"}) {
        QVERIFY2(std::filesystem::exists(*linux_dir / f), f);
    }
    QVERIFY(load_config_string(read(*linux_dir / "agence.yaml")).config.has_value());
    const auto script = read(*linux_dir / "install.sh");
    QVERIFY(script.find("conf='/etc/tlsrelay/agence.yaml'") != std::string::npos);
    QVERIFY(script.find("'/etc/tlsrelay/agence/whitelist.yaml'") != std::string::npos);
    QVERIFY(script.find("pki install -c \"$conf\" --from \"$here/kit\"") != std::string::npos);
    QVERIFY(script.find("pki crl -c \"$conf\" \"$here/crl.pem\"") != std::string::npos);
    QVERIFY(read(*linux_dir / "LISEZMOI.txt").find("pki activate") != std::string::npos);
    // Un paquet existant n'est pas écrasé.
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    QVERIFY(!window.export_package(*request).has_value());
    QCOMPARE(reports.size(), 1);

    // Windows, sans kit : chemins Linux signalés comme relatifs, script PowerShell.
    request->out_dir = dir / "windows";
    request->platform = TargetPlatform::windows_host;
    request->kit_dir.reset();
    request->crl_file.reset();
    const auto warnings = export_warnings(*request);
    QVERIFY(std::any_of(warnings.begin(), warnings.end(),
                        [](const std::string& w) { return w.find("credentials.pki_root") != std::string::npos; }));
    const auto win_dir = window.export_package(*request);
    QVERIFY(win_dir.has_value());
    const auto ps1 = read(*win_dir / "install.ps1");
    QVERIFY(ps1.rfind("\xEF\xBB\xBF", 0) == 0);
    QVERIFY(ps1.find("Run check-config -c $conf") != std::string::npos);
    const auto readme = read(*win_dir / "LISEZMOI.txt");
    QVERIFY(readme.find("pki gen-csr") != std::string::npos);
    QVERIFY(readme.find("Points d'attention") != std::string::npos);

    // Kit incomplet refusé.
    std::filesystem::remove(dir / "kit" / "chain.pem");
    request->out_dir = dir / "autre";
    request->kit_dir = dir / "kit";
    QVERIFY_THROWS_EXCEPTION(std::runtime_error, admin::export_package(*request));
}

void AdminTest::diff_preview_lists_changes() {
    const std::vector<FileChange> changes = {
        {"/tmp/a.yaml", std::string("mode: server\nport: 1\n"), "mode: server\nport: 2\n"},
        {"/tmp/b.yaml", std::nullopt, "peers: []\n"},
        {"/tmp/c.yaml", std::string("same\n"), "same\n"},
    };
    const auto html = DiffDialog::render(changes);
    QVERIFY(html.contains("- port: 1"));
    QVERIFY(html.contains("+ port: 2"));
    QVERIFY(html.contains("b.yaml"));
    QVERIFY(!html.contains("c.yaml"));
}

QTEST_MAIN(AdminTest)
#include "test_admin.moc"
