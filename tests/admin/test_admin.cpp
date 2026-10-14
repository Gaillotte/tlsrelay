// Tests de l'éditeur tlsrelay-admin (Qt Test, plateforme « offscreen »).

#include "config_form.hpp"
#include "deployment.hpp"
#include "diff_dialog.hpp"
#include "document.hpp"
#include "export_dialog.hpp"
#include "main_window.hpp"
#include "pki_panel.hpp"
#include "sign_dialog.hpp"
#include "tlsrelay/pki/audit.hpp"
#include "tlsrelay/pki/request.hpp"
#include "whitelist_editor.hpp"

#include <QAction>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QTimer>
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
    void pki_panel_full_cycle();
    void pki_panel_refuses_wrong_passphrase_and_bad_directory();
    void sign_dialog_inspects_request();
    void pki_root_change_preparation();
    // Dialogues modaux (TESTS.md §6.4, CT-01 à CT-06).
    void export_dialog_builds_request_and_warns();
    void diff_dialog_is_shown_and_controls_saving();
    void revoke_and_crl_dialogs();
    void root_change_dialog_creates_ca_and_prepares_files();
    void sign_and_create_dialogs();
    void main_window_navigation_and_close();
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

    // Modifications éloignées : les lignes sans changement entre elles sont résumées.
    std::string before, after;
    for (int i = 0; i < 20; ++i) {
        before += "ligne " + std::to_string(i) + "\n";
        after += (i == 1 || i == 18 ? "modifiée " : "ligne ") + std::to_string(i) + "\n";
    }
    const auto spread = DiffDialog::render({{"/tmp/d.yaml", before, after}});
    QVERIFY(spread.contains("…"));
    QVERIFY(!spread.contains("ligne 10"));
}

namespace {

const std::string kPass = "phrase de passe d'essai";

// Instance factice : génération avec demande de signature, comme « pki gen-csr ».
std::filesystem::path make_request(const std::filesystem::path& pki_root, const std::string& subject) {
    return pki::generate_csr(pki_root, subject, {}).csr;
}

int rows_with(QTableWidget* table, int column, const QString& text) {
    int n = 0;
    for (int r = 0; r < table->rowCount(); ++r) n += table->item(r, column)->text() == text;
    return n;
}

}  // namespace

void AdminTest::pki_panel_full_cycle() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    PkiPanel panel;
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    panel.inform = [](const QString&) {};
    int asked = 0;
    panel.ask_passphrase = [&](const QString&, bool) -> std::optional<std::string> {
        ++asked;
        return kPass;
    };
    QVERIFY(panel.create_authority(dir / "ac", "Essai"));
    QVERIFY(panel.info().has_value());
    QCOMPARE(QString::fromStdString(panel.info()->root.subject), QString("CN=Essai AC Racine,O=Essai"));

    // Signature d'un serveur et d'un client.
    SignOptions server{make_request(dir / "srv", "CN=relay.essai,O=Essai"), pki::Role::server, {"relay.essai"}, 365,
                       false, dir / "kit-srv"};
    const auto s = panel.sign(server);
    QVERIFY2(s.has_value(), qPrintable(reports.join("\n")));
    QVERIFY(std::filesystem::exists(dir / "kit-srv" / "trust-issuer.pem"));
    SignOptions client{make_request(dir / "cli", "CN=agence.essai,O=Essai"), pki::Role::client, {}, 30, false,
                       dir / "kit-cli"};
    const auto c = panel.sign(client);
    QVERIFY(c.has_value());
    QCOMPARE(panel.inventory()->rowCount(), 2);
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "valide"), 2);

    // Même sujet sans renouvellement : refusé ; avec : l'ancien est remplacé.
    client.csr = make_request(dir / "cli", "CN=agence.essai,O=Essai");
    QVERIFY(!panel.sign(client).has_value());
    QVERIFY(reports.last().contains("déjà attribué"));
    client.renew = true;
    client.out = dir / "kit-cli2";
    QVERIFY(panel.sign(client).has_value());
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "remplacé"), 1);

    // Filtres : le certificat de 30 jours expire bientôt.
    panel.set_filter(PkiPanel::expiring);
    QCOMPARE(panel.inventory()->rowCount(), 1);
    panel.set_filter(PkiPanel::retired);
    QCOMPARE(panel.inventory()->rowCount(), 1);
    panel.set_filter(PkiPanel::all);

    // Révocation : inventaire, CRL publiées et copie à déployer.
    QVERIFY(panel.revoke(s->serial, pki::RevocationReason::key_compromise, 30, dir / "deploy" / "crl.pem"));
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "révoqué"), 1);
    QCOMPARE(panel.info()->revoked, size_t(1));
    QCOMPARE(panel.info()->crl_number, std::uint64_t(1));
    QVERIFY(read(dir / "deploy" / "crl.pem").find("BEGIN X509 CRL") != std::string::npos);
    QVERIFY(!panel.revoke(s->serial, pki::RevocationReason::unspecified, 30, std::nullopt));  // déjà révoqué
    QVERIFY(panel.publish_crl(7, std::nullopt).has_value());
    QCOMPARE(panel.info()->crl_number, std::uint64_t(2));

    // Journal d'audit : création, 3 signatures, révocation, 2 CRL.
    QCOMPARE(panel.audit()->rowCount(), 7);
    QVERIFY(panel.audit_status()->text().contains("intacte"));

    // Un autre panneau reprend le même répertoire (mini-AC de la ligne de commande).
    PkiPanel other;
    other.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    QVERIFY(other.open_authority(dir / "ac"));
    QCOMPARE(other.inventory()->rowCount(), 3);

    // Journal altéré : signalé.
    auto log = read(dir / "ac" / "audit.log");
    log.replace(log.find("sign"), 4, "s1gn");
    write(dir / "ac" / "audit.log", log);
    other.refresh();
    QVERIFY(other.audit_status()->text().contains("altéré"));
    QVERIFY(asked >= 6);
}

void AdminTest::pki_panel_refuses_wrong_passphrase_and_bad_directory() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    PkiPanel panel;
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    QVERIFY(!panel.open_authority(dir / "rien"));
    QVERIFY(reports.last().contains("n'est pas un répertoire d'AC"));
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return std::string("courte"); };
    QVERIFY(!panel.create_authority(dir / "ac", "Essai"));
    QVERIFY(reports.last().contains("trop courte"));
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };
    QVERIFY(panel.create_authority(dir / "ac", "Essai"));
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return std::string("mauvaise phrase !"); };
    const SignOptions options{make_request(dir / "srv", "CN=x.essai"), pki::Role::server, {"x.essai"}, 365, false,
                              dir / "kit"};
    QVERIFY(!panel.sign(options).has_value());
    QVERIFY(reports.last().contains("phrase de passe incorrecte"));
    QCOMPARE(panel.inventory()->rowCount(), 0);
    // Saisie annulée : rien n'est fait, sans message.
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return std::nullopt; };
    const auto count = reports.size();
    QVERIFY(!panel.publish_crl(30, std::nullopt).has_value());
    QCOMPARE(reports.size(), count);
}

void AdminTest::sign_dialog_inspects_request() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    const auto csr = make_request(dir / "srv", "CN=relay.essai,O=Essai");
    SignDialog dialog(false, {}, pki::Role::server, nullptr);
    dialog.set_csr(to_qstring(csr));
    QVERIFY(dialog.request_description().contains("CN=relay.essai,O=Essai"));
    QVERIFY(!dialog.ready());  // serveur sans SAN
    dialog.set_sans("relay.essai, ip:192.0.2.10");
    QVERIFY(dialog.ready());
    const auto options = dialog.options();
    QCOMPARE(options.sans.size(), size_t(2));
    QCOMPARE(options.out, csr.parent_path() / "kit");
    dialog.set_sans("ip:999.1.1.1");
    QVERIFY(!dialog.ready());
    write(dir / "faux.csr", "pas une demande");
    dialog.set_csr(to_qstring(dir / "faux.csr"));
    QVERIFY(dialog.request_description().contains("refusée"));
    QVERIFY(!dialog.ready());

    // Renouvellement : un sujet différent du certificat sélectionné est signalé.
    SignDialog renew(true, "CN=autre,O=Essai", pki::Role::client, nullptr);
    renew.set_csr(to_qstring(make_request(dir / "cli", "CN=agence.essai,O=Essai")));
    QVERIFY(renew.options().renew);
    QVERIFY(renew.request_description().contains("attention"));
    QVERIFY(renew.ready());
}

void AdminTest::pki_root_change_preparation() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    PkiPanel panel;
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };
    QVERIFY(panel.create_authority(dir / "ac2", "Essai"));
    QVERIFY(panel.create_authority(dir / "ac", "Essai"));  // AC en service
    QVERIFY(!panel.prepare_root_change(dir / "ac", dir / "x"));
    QVERIFY(reports.last().contains("même racine"));
    QVERIFY(panel.prepare_root_change(dir / "ac2", dir / "transition"));
    for (const char* f : {"serveur/trust-roots.pem", "serveur/trust-issuer.pem", "client/trust-roots.pem", "LISEZMOI.txt"}) {
        QVERIFY2(std::filesystem::exists(dir / "transition" / f), f);
    }
    QCOMPARE(panel.audit()->item(panel.audit()->rowCount() - 1, 2)->text(), QString("root-transition"));
}

namespace {

// Agit sur la prochaine fenêtre modale de type T qui s'ouvre (QDialog::exec(),
// QFileDialog, QInputDialog, QMessageBox) : les dialogues sont pilotés comme
// par un utilisateur. Chaque fenêtre n'est traitée qu'une fois ; sans fenêtre
// dans les 10 s, l'attente s'arrête (le test échoue alors sur ses vérifications).
template <class T>
void on_modal(std::function<void(T*)> action) {
    auto* timer = new QTimer;
    auto deadline = std::make_shared<QDeadlineTimer>(10000);
    QObject::connect(timer, &QTimer::timeout, timer, [timer, deadline, action] {
        auto* w = qobject_cast<T*>(QApplication::activeModalWidget());
        if (!w || w->property("pris_en_charge").toBool()) {
            if (deadline->hasExpired()) timer->deleteLater();
            return;
        }
        w->setProperty("pris_en_charge", true);
        timer->stop();
        timer->deleteLater();
        action(w);
    });
    timer->start(20);
}

void press(QWidget* dialog, QDialogButtonBox::StandardButton which) {
    auto* box = dialog->findChild<QDialogButtonBox*>();
    QVERIFY(box && box->button(which));
    box->button(which)->click();
}

void choose_path(QFileDialog* dialog, const std::filesystem::path& path) {
    if (std::filesystem::is_directory(path)) {
        // Choix d'un répertoire : il devient le répertoire courant du sélecteur.
        dialog->setDirectory(to_qstring(path));
        dialog->selectFile(QString());
    } else {
        // Nom saisi comme par l'utilisateur (selectFile ne remplace pas un champ qui a le focus).
        dialog->setDirectory(to_qstring(path.parent_path()));
        dialog->findChild<QLineEdit*>("fileNameEdit")->setText(to_qstring(path.filename()));
    }
    static_cast<QDialog*>(dialog)->accept();  // QFileDialog::accept : contrôle du chemin choisi
}

void answer_text(QInputDialog* dialog, const QString& text) {
    dialog->setTextValue(text);
    dialog->accept();
}

QPushButton* button(QWidget* parent, const QString& text) {
    for (auto* b : parent->findChildren<QPushButton*>()) {
        if (b->text() == text) return b;
    }
    return nullptr;
}

void trigger(QWidget* window, const QString& text) {
    for (auto* a : window->findChildren<QAction*>()) {
        if (a->text().remove('&') == text) {
            a->trigger();
            return;
        }
    }
    QFAIL(qPrintable("action absente : " + text));
}

// AC créée hors du panneau (le panneau testé garde sa saisie de phrase de passe par défaut).
std::filesystem::path make_authority(const std::filesystem::path& dir) {
    pki::AuthorityOptions options;
    options.organization = "Essai";
    pki::init_authority(dir, kPass, options);
    return dir;
}

}  // namespace

void AdminTest::export_dialog_builds_request_and_warns() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    MainWindow window;
    window.show();
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };

    // Document invalide : export refusé avant le dialogue.
    window.new_document(Mode::server);
    trigger(&window, "Exporter le paquet de déploiement…");
    QCOMPARE(reports.size(), 1);
    QVERIFY(reports.last().contains("avant d'exporter"));

    write(dir / "agence.yaml", kServer);
    QVERIFY(window.open_file(dir / "agence.yaml"));
    std::filesystem::create_directories(dir / "kit");
    for (const char* f : {"cert.pem", "chain.pem", "trust-roots.pem", "trust-issuer.pem"}) write(dir / "kit" / f, "PEM\n");
    write(dir / "crl.pem", "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n");

    ExportRequest seen;
    QString warnings;
    bool info_shown = false;
    on_modal<ExportDialog>([&](ExportDialog* d) {
        // Sans répertoire de sortie, « Exporter » ne ferme pas le dialogue.
        press(d, QDialogButtonBox::Ok);
        QVERIFY(d->isVisible());
        d->findChild<QLineEdit*>("sortie")->setText(to_qstring(dir / "paquets"));
        d->findChild<QComboBox*>("plateforme")->setCurrentIndex(1);  // Windows
        d->findChild<QLineEdit*>("kit")->setText(to_qstring(dir / "kit"));
        d->findChild<QLineEdit*>("crl")->setText(to_qstring(dir / "crl.pem"));
        seen = d->request();
        warnings = d->findChild<QLabel*>("avertissements")->text();
        on_modal<QMessageBox>([&](QMessageBox* box) {
            info_shown = box->text().contains("LISEZMOI.txt");
            box->accept();
        });
        press(d, QDialogButtonBox::Ok);
    });
    trigger(&window, "Exporter le paquet de déploiement…");
    QVERIFY2(reports.size() == 1, qPrintable(reports.join("\n")));
    QCOMPARE(seen.out_dir, dir / "paquets");
    QVERIFY(seen.platform == TargetPlatform::windows_host);
    QCOMPARE(*seen.kit_dir, dir / "kit");
    QCOMPARE(*seen.crl_file, dir / "crl.pem");
    QVERIFY2(warnings.contains("credentials.pki_root"), qPrintable(warnings));  // chemin Linux pour Windows
    QVERIFY(info_shown);
    QVERIFY(std::filesystem::exists(dir / "paquets" / "agence" / "install.ps1"));

    // Annulation : rien n'est créé.
    on_modal<ExportDialog>([&](ExportDialog* d) {
        d->findChild<QLineEdit*>("sortie")->setText(to_qstring(dir / "annule"));
        press(d, QDialogButtonBox::Cancel);
    });
    trigger(&window, "Exporter le paquet de déploiement…");
    QVERIFY(!std::filesystem::exists(dir / "annule"));
}

void AdminTest::diff_dialog_is_shown_and_controls_saving() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    write(dir / "agence.yaml", kServer);
    write(dir / "whitelist.yaml", "peers:\n  - { name: lyon, ip: 192.0.2.10, ports: [mtls], subject: \"CN=lyon\" }\n");
    MainWindow window;  // confirmation par défaut : le dialogue d'aperçu
    window.show();
    window.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    QVERIFY(window.open_file(dir / "agence.yaml"));

    // Premier enregistrement : les deux fichiers sont réécrits sous forme normalisée.
    window.config_form()->set_value("limits.max_channels", "200");
    QString shown;
    on_modal<DiffDialog>([&](DiffDialog* d) {
        shown = d->findChild<QTextBrowser*>()->toPlainText();
        press(d, QDialogButtonBox::Save);
    });
    QVERIFY(window.save());
    QVERIFY2(shown.contains("agence.yaml") && shown.contains("max_channels: 200"), qPrintable(shown));
    QVERIFY(shown.contains("whitelist.yaml"));
    QVERIFY(std::filesystem::exists(dir / "agence.yaml.bak"));
    QCOMPARE(load_config_file(dir / "agence.yaml").config->limits.max_channels, 200u);

    // Seule la configuration change ensuite : l'aperçu ne montre qu'elle.
    window.config_form()->set_value("limits.max_channels", "250");
    on_modal<DiffDialog>([&](DiffDialog* d) {
        shown = d->findChild<QTextBrowser*>()->toPlainText();
        press(d, QDialogButtonBox::Save);
    });
    QVERIFY(window.save());
    QVERIFY2(shown.contains("max_channels: 250") && !shown.contains("whitelist.yaml"), qPrintable(shown));
    QCOMPARE(load_config_file(dir / "agence.yaml").config->limits.max_channels, 250u);

    // Annulation : rien n'est écrit, le document reste modifié.
    window.config_form()->set_value("limits.max_channels", "300");
    on_modal<DiffDialog>([&](DiffDialog* d) { press(d, QDialogButtonBox::Cancel); });
    QVERIFY(!window.save());
    QVERIFY(window.is_modified());
    QCOMPARE(load_config_file(dir / "agence.yaml").config->limits.max_channels, 250u);
}

void AdminTest::revoke_and_crl_dialogs() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    make_authority(dir / "ac");
    PkiPanel panel;
    QStringList reports, infos;
    panel.report = [&](const QString& m) { reports << m; };
    panel.inform = [&](const QString& m) { infos << m; };
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };
    QVERIFY(panel.open_authority(dir / "ac"));
    const auto a = panel.sign({make_request(dir / "a", "CN=a.essai"), pki::Role::client, {}, 365, false, dir / "kit-a"});
    const auto b = panel.sign({make_request(dir / "b", "CN=b.essai"), pki::Role::client, {}, 365, false, dir / "kit-b"});
    QVERIFY(a && b);

    // Révocation de a : motif, validité et copie des CRL choisis dans le dialogue.
    auto row_of = [&](const std::string& serial) {
        for (int r = 0; r < panel.inventory()->rowCount(); ++r) {
            if (panel.inventory()->item(r, PkiPanel::serial_column)->text().toStdString() == serial) return r;
        }
        return -1;
    };
    panel.inventory()->selectRow(row_of(a->serial));
    on_modal<QDialog>([&](QDialog* d) {
        d->findChild<QComboBox*>()->setCurrentIndex(0);  // keyCompromise
        d->findChild<QSpinBox*>()->setValue(7);
        d->findChild<QLineEdit*>()->setText(to_qstring(dir / "deploy" / "crl.pem"));
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Révoquer…")->click();
    QVERIFY2(reports.isEmpty(), qPrintable(reports.join("\n")));
    QVERIFY(infos.last().contains(QString::fromStdString(a->serial)));
    QCOMPARE(panel.inventory()->item(row_of(a->serial), PkiPanel::status_column)->text(), QString("révoqué"));
    QVERIFY(panel.inventory()->item(row_of(a->serial), PkiPanel::revocation_column)->text().contains("keyCompromise"));
    QVERIFY(read(dir / "deploy" / "crl.pem").find("BEGIN X509 CRL") != std::string::npos);

    // Publication des CRL : 10 jours, sans copie.
    on_modal<QDialog>([&](QDialog* d) {
        d->findChild<QSpinBox*>()->setValue(10);
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Publier les CRL…")->click();
    QVERIFY2(infos.last().contains("CRL n° 2"), qPrintable(infos.last()));
    QCOMPARE(panel.info()->crl_number, std::uint64_t(2));

    // Révocation annulée : b reste valide.
    panel.inventory()->selectRow(row_of(b->serial));
    on_modal<QDialog>([&](QDialog* d) { press(d, QDialogButtonBox::Cancel); });
    button(&panel, "Révoquer…")->click();
    QCOMPARE(panel.inventory()->item(row_of(b->serial), PkiPanel::status_column)->text(), QString("valide"));
}

void AdminTest::root_change_dialog_creates_ca_and_prepares_files() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    make_authority(dir / "ac");
    std::filesystem::create_directories(dir / "nouvelle");
    PkiPanel panel;  // saisie de la phrase de passe par défaut : deux fenêtres de saisie
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    QVERIFY(panel.open_authority(dir / "ac"));

    // Création de la nouvelle AC depuis l'assistant ; première tentative : saisies différentes.
    auto create_new_ca = [&](QDialog* d, const QString& second) {
        on_modal<QFileDialog>([&, second](QFileDialog* f) {
            on_modal<QInputDialog>([&, second](QInputDialog* first) {
                on_modal<QInputDialog>([second](QInputDialog* confirm) { answer_text(confirm, second); });
                answer_text(first, QString::fromStdString(kPass));
            });
            choose_path(f, dir / "nouvelle");
        });
        button(d, "Créer la nouvelle AC…")->click();
    };
    QString readme;
    on_modal<QDialog>([&](QDialog* d) {
        const auto edits = d->findChildren<QLineEdit*>();
        QCOMPARE(edits.size(), 2);
        press(d, QDialogButtonBox::Ok);  // champs vides : rien
        create_new_ca(d, "autre phrase de passe");
        QVERIFY(edits[0]->text().isEmpty());
        create_new_ca(d, QString::fromStdString(kPass));
        QCOMPARE(to_path(edits[0]->text()), dir / "nouvelle");
        edits[1]->setText(to_qstring(dir / "transition"));
        press(d, QDialogButtonBox::Ok);
        readme = d->findChild<QTextBrowser*>()->toPlainText();
        press(d, QDialogButtonBox::Close);
    });
    button(&panel, "Changement de racine…")->click();
    QVERIFY(reports.contains("Les deux saisies diffèrent."));
    QVERIFY(std::filesystem::exists(dir / "nouvelle" / "root.cert.pem"));
    QVERIFY(pki::describe_authority(dir / "nouvelle").root.subject.find("O=Essai") != std::string::npos);
    QVERIFY(std::filesystem::exists(dir / "transition" / "LISEZMOI.txt"));
    QVERIFY(!readme.isEmpty());
}

void AdminTest::sign_and_create_dialogs() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    std::filesystem::create_directories(dir / "ac");
    PkiPanel panel;
    QStringList reports, infos;
    panel.report = [&](const QString& m) { reports << m; };
    panel.inform = [&](const QString& m) { infos << m; };
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };

    // « Créer une AC… » : répertoire, organisation.
    on_modal<QFileDialog>([&](QFileDialog* f) {
        on_modal<QInputDialog>([](QInputDialog* org) { answer_text(org, "Essai"); });
        choose_path(f, dir / "ac");
    });
    button(&panel, "Créer une AC…")->click();
    QVERIFY2(panel.info().has_value(), qPrintable(reports.join("\n")));
    QVERIFY(infos.last().contains("AC créée"));

    // « Ouvrir une AC… » dans un autre panneau.
    PkiPanel other;
    other.report = [&](const QString& m) { reports << m; };
    on_modal<QFileDialog>([&](QFileDialog* f) { choose_path(f, dir / "ac"); });
    button(&other, "Ouvrir une AC…")->click();
    QCOMPARE(other.authority(), dir / "ac");

    // Signature : fichier illisible signalé, puis demande avec extension SAN (ignorée par l'AC).
    std::string san_error;
    const auto sans = pki::parse_sans({"relay.essai"}, san_error);
    QVERIFY(sans.has_value());
    const auto csr = pki::generate_csr(dir / "srv", "CN=relay.essai,O=Essai", *sans).csr;
    QString unreadable, description;
    on_modal<SignDialog>([&](SignDialog* d) {
        d->set_csr(to_qstring(dir / "absent.csr"));
        unreadable = d->request_description();
        d->set_csr(to_qstring(csr));
        d->set_sans("relay.essai");
        d->set_out(to_qstring(dir / "kit"));
        description = d->request_description();
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Signer une demande…")->click();
    QCOMPARE(unreadable, QString("fichier illisible"));
    QVERIFY2(description.contains("extensions demandées, ignorées"), qPrintable(description));
    QVERIFY2(infos.last().contains("Certificat émis"), qPrintable(infos.last()));
    QVERIFY(std::filesystem::exists(dir / "kit" / "cert.pem"));

    // Renouvellement du certificat sélectionné : sujet et rôle repris.
    panel.inventory()->selectRow(0);
    QString expected;
    on_modal<SignDialog>([&](SignDialog* d) {
        QVERIFY(d->options().renew);
        QVERIFY(d->options().role == pki::Role::server);
        d->set_csr(to_qstring(pki::generate_csr(dir / "srv", "CN=relay.essai,O=Essai", {}).csr));
        d->set_sans("relay.essai");
        d->set_out(to_qstring(dir / "kit2"));
        expected = d->request_description();
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Renouveler…")->click();
    QVERIFY(!expected.contains("attention"));  // même sujet
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "remplacé"), 1);
}

void AdminTest::main_window_navigation_and_close() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    // Configuration avec une erreur, une clé ignorée ; liste blanche avec une erreur et une clé ignorée.
    write(dir / "agence.yaml", std::string(kServer) + "inconnu: 1\n");
    {
        auto text = read(dir / "agence.yaml");
        text.replace(text.find("0.0.0.0:9003"), 12, "0.0.0.0:99999");
        write(dir / "agence.yaml", text);
    }
    write(dir / "whitelist.yaml", "peers:\n  - { name: a, ip: 10.0.0.1, ports: [plain], note: x }\n  - { name: b, ip: 300.0.0.1 }\n");
    MainWindow window;
    window.show();
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    window.confirm_save = [](const std::vector<FileChange>&) { return true; };
    QVERIFY(window.open_file(dir / "agence.yaml"));
    QVERIFY(window.error_count() >= 2);

    // Activation de chaque erreur : onglet et champ correspondants.
    QTabWidget* tabs = nullptr;
    for (auto* t : window.findChildren<QTabWidget*>()) {
        if (t->count() == 3) tabs = t;
    }
    QVERIFY(tabs);
    bool config_seen = false, whitelist_seen = false;
    QStringList notes;
    for (int i = 0; i < window.issues()->count(); ++i) {
        auto* item = window.issues()->item(i);
        notes << item->text();
        emit window.issues()->itemActivated(item);
        if (item->text().startsWith("Configuration — ports")) config_seen = tabs->currentIndex() == 0;
        if (item->text().startsWith("Liste blanche — peers[1]")) {
            whitelist_seen = tabs->currentIndex() == 1 && window.whitelist_editor()->table()->currentRow() == 1;
        }
    }
    QVERIFY2(config_seen && whitelist_seen, qPrintable(notes.join("\n")));
    QVERIFY2(notes.join("\n").contains("inconnu ignoré"), qPrintable(notes.join("\n")));
    QVERIFY2(notes.join("\n").contains("Liste blanche : peers[0].note ignoré"), qPrintable(notes.join("\n")));

    // À propos : versions de tlsrelay, d'OpenSSL et de Qt.
    QString about;
    on_modal<QMessageBox>([&](QMessageBox* box) {
        about = box->text();
        box->accept();
    });
    trigger(&window, "À propos");
    QVERIFY2(about.contains("OpenSSL") && about.contains(qVersion()), qPrintable(about));

    // Lecture et écriture impossibles.
    QVERIFY(!window.open_file(dir / "absent.yaml"));
    QVERIFY(reports.last().contains("Lecture impossible"));
    write(dir / "valide.yaml", kServer);
    write(dir / "whitelist.yaml", "peers: []\n");
    QVERIFY(window.open_file(dir / "valide.yaml"));
    write(dir / "fichier", "x");
    QVERIFY(!window.save_to(dir / "fichier" / "x.yaml"));
    QVERIFY(reports.last().contains("Enregistrement impossible"));

    // Ouvrir avec des modifications en cours : « Non » garde le document, puis ouverture par le sélecteur.
    window.config_form()->set_value("limits.max_channels", "10");
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::No)->click(); });
    trigger(&window, "Ouvrir…");
    QVERIFY(window.is_modified());
    window.config_form()->set_value("limits.max_channels", "");
    QVERIFY(window.save());
    on_modal<QFileDialog>([&](QFileDialog* f) { choose_path(f, dir / "agence.yaml"); });
    trigger(&window, "Ouvrir…");
    QCOMPARE(window.config_path(), dir / "agence.yaml");

    // Enregistrer sous : chemin choisi dans le sélecteur.
    QVERIFY(window.open_file(dir / "valide.yaml"));
    on_modal<QFileDialog>([&](QFileDialog* f) { choose_path(f, dir / "copie.yaml"); });
    trigger(&window, "Enregistrer sous…");
    QVERIFY(load_config_file(dir / "copie.yaml").config.has_value());

    // Fermeture avec des modifications : Annuler, Ignorer, puis Enregistrer.
    window.config_form()->set_value("limits.max_channels", "20");
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::Cancel)->click(); });
    QVERIFY(!window.close());
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::Save)->click(); });
    QVERIFY(window.close());
    QCOMPARE(load_config_file(dir / "copie.yaml").config->limits.max_channels, 20u);
    MainWindow second;
    second.show();
    QVERIFY(second.open_file(dir / "copie.yaml"));
    second.config_form()->set_value("limits.max_channels", "30");
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::Discard)->click(); });
    QVERIFY(second.close());
    QCOMPARE(load_config_file(dir / "copie.yaml").config->limits.max_channels, 20u);
    MainWindow third;  // sans modification : fermeture sans question
    QVERIFY(third.close());
}

QTEST_MAIN(AdminTest)
#include "test_admin.moc"
