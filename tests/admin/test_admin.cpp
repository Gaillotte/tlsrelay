// Tests of the tlsrelay-admin editor (Qt Test, "offscreen" platform).

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
    for (const auto& i : issues) s += i.path + ": " + i.message + "\n";
    return s;
}

const char* kServer = R"(
mode: server
instance: branch
credentials: { pki_root: /etc/tlsrelay/branch/pki }
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
    // Modal dialogs (TESTS.md §6.4, CT-01 to CT-06).
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

// Editor/service parity: a file loaded into the form produces the
// same errors (paths and messages) as when read directly by the service.
void AdminTest::validation_matches_service() {
    const std::vector<std::string> corpus = {
        kServer,
        "mode: client\n",
        "mode: server\nports: { plain: { listen: \"0.0.0.0:9001\" } }\n",
        "mode: bridge\n",
        "mode: client\ninstance: \"invalid name!\"\nports: { tls: { listen: \"127.0.0.1:7002\" } }\n",
        "mode: client\nports: { tls: { listen: \"127.0.0.1:7002\", upstream: \"r:9002\" } }\n",
        "mode: client\nlimits: { idle_timeout: 5 minutes, session_jitter: 80%, max_channels: -1 }\n"
        "ports: { plain: { listen: \"127.0.0.1:7001\", upstream: \"r:9001\", server_name: x } }\n",
        "mode: server\ndestination: { address: d, port: 70000, dial_retries: 0 }\nwhitelist: { file: w.yaml }\n"
        "ports: { plain: { listen: \"0.0.0.0:9001\", upstream: \"r:1\" }, tls: { listen: \"0.0.0.0:9001\" } }\n",
        "mode: server\nsource_address: 1.2.3.4\ndestination: { address: d, port: 1 }\nwhitelist: { file: w }\n"
        "ports: { plain: { listen: \"host:9001\" } }\nlogging: { level: verbose, output: syslog }\n",
        "mode: client\ncredentials: { watch: maybe }\nadmin: { enabled: sure, endpoint: \"\" }\n"
        "ports: { mtls: { listen: \"[::1]:7003\", upstream: \"[2001:db8::1]:9003\", server_name: relay } }\n",
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
    form.set_value("limits.idle_timeout", "five minutes");
    form.set_value("destination.port", "99999");
    const auto result = form.validate();
    QVERIFY(!result.config);
    auto* idle = form.widget_for("limits.idle_timeout");
    QVERIFY(idle->property("invalid").toBool());
    QVERIFY(idle->toolTip().contains("invalid duration"));
    QVERIFY(form.widget_for("destination.port")->property("invalid").toBool());
    // An error on a section points to the section.
    QCOMPARE(form.widget_for("ports.tls"), form.widget_for("ports.tls.unknown"));
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
    QVERIFY(form.is_shown("destination.address"));  // filled in: stays visible so it can be fixed
    const auto result = form.validate();
    QVERIFY(QString::fromStdString(issues_text(result.errors)).contains("destination: not applicable in client mode"));
    QVERIFY(!form.is_shown("ports.plain.server_name"));
}

void AdminTest::whitelist_editor_round_trip_and_marks() {
    WhitelistEditor editor;
    const std::string text = "peers:\n"
                             "  - { name: lyon, ip: 192.0.2.10, ports: [mtls], subject: \"CN=lyon,O=E\" }\n"
                             "  - { name: nantes, ip: 198.51.100.0/24 }\n"
                             "  - { name: x, ip: 203.0.113.1, ports: [ftp], colour: blue }\n";
    const auto ignored = editor.load_yaml(text);
    QCOMPARE(ignored.size(), size_t(3));  // port ftp, empty port list, key colour
    QCOMPARE(editor.table()->rowCount(), 3);
    const auto peers = editor.peers();
    QVERIFY(peers[0].ports && peers[0].ports->count(PortKind::mtls));
    QVERIFY(!peers[1].ports);
    QVERIFY(editor.validate().whitelist != nullptr);

    // Errors: duplicate name, invalid IP, mtls without subject.
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
    write(dir / "branch.yaml", std::string("# original comment\n") + kServer);
    write(dir / "whitelist.yaml", "peers:\n  - { name: lyon, ip: 192.0.2.10, ports: [mtls], subject: \"CN=lyon\" }\n");

    MainWindow window;
    std::vector<FileChange> shown;
    window.confirm_save = [&](const std::vector<FileChange>& changes) {
        shown = changes;
        return true;
    };
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    QVERIFY(window.open_file(dir / "branch.yaml"));
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

    // Files rewritten, originals in .bak, read back identically by the service.
    QVERIFY(read(dir / "branch.yaml.bak").find("# original comment") != std::string::npos);
    QVERIFY(std::filesystem::exists(dir / "whitelist.yaml.bak"));
    const auto saved = load_config_file(dir / "branch.yaml");
    QVERIFY2(saved.config.has_value(), issues_text(saved.errors).c_str());
    QCOMPARE(saved.config->limits.max_channels, 200u);
    const auto wl = whitelist::Whitelist::load_file(dir / "whitelist.yaml");
    QVERIFY(wl.whitelist);
    QCOMPARE(wl.whitelist->peers().size(), size_t(2));
    QVERIFY(!window.is_modified());

    // Second save without changes: nothing to confirm, nothing written.
    shown.clear();
    QVERIFY(window.save());
    QVERIFY(shown.empty());

    // Preview refused: nothing is written.
    window.config_form()->set_value("limits.max_channels", "300");
    window.confirm_save = [](const std::vector<FileChange>&) { return false; };
    QVERIFY(!window.save());
    QCOMPARE(load_config_file(dir / "branch.yaml").config->limits.max_channels, 200u);
}

void AdminTest::save_refused_while_invalid() {
    QTemporaryDir tmp;
    MainWindow window;
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    window.confirm_save = [](const std::vector<FileChange>&) { return true; };
    window.new_document(Mode::server);
    QVERIFY(window.error_count() > 0);  // ports, destination, whitelist missing
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
    form->set_value("instance", "workstation");
    form->set_port_enabled(PortKind::tls, true);
    form->set_value("ports.tls.listen", "127.0.0.1:7002");
    form->set_value("ports.tls.upstream", "relay.example:9002");
    form->set_value("ports.tls.server_name", "relay.example");
    form->set_value("credentials.pki_root", "/etc/tlsrelay/workstation/pki");
    QCOMPARE(window.error_count(), 0);
    QVERIFY(window.save_to(dir / "workstation.yaml"));
    const auto text = read(dir / "workstation.yaml");
    QVERIFY(text.rfind("# Written by tlsrelay-admin", 0) == 0);
    QVERIFY(text.find("limits") == std::string::npos);  // default values omitted
    QVERIFY(!std::filesystem::exists(dir / "workstation.yaml.bak"));
    QVERIFY(load_config_string(text).config.has_value());
}

void AdminTest::export_package_for_linux_and_windows() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    MainWindow window;
    window.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    write(dir / "branch.yaml", std::string(kServer).replace(std::string(kServer).find("whitelist.yaml"), 14,
                                                            "/etc/tlsrelay/branch/whitelist.yaml"));
    QVERIFY(window.open_file(dir / "branch.yaml"));
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
    QCOMPARE(*linux_dir, dir / "linux" / "branch");
    for (const char* f : {"branch.yaml", "whitelist.yaml", "kit/cert.pem", "crl.pem", "install.sh", "README.txt"}) {
        QVERIFY2(std::filesystem::exists(*linux_dir / f), f);
    }
    QVERIFY(load_config_string(read(*linux_dir / "branch.yaml")).config.has_value());
    const auto script = read(*linux_dir / "install.sh");
    QVERIFY(script.find("conf='/etc/tlsrelay/branch.yaml'") != std::string::npos);
    QVERIFY(script.find("'/etc/tlsrelay/branch/whitelist.yaml'") != std::string::npos);
    QVERIFY(script.find("pki install -c \"$conf\" --from \"$here/kit\"") != std::string::npos);
    QVERIFY(script.find("pki crl -c \"$conf\" \"$here/crl.pem\"") != std::string::npos);
    QVERIFY(read(*linux_dir / "README.txt").find("pki activate") != std::string::npos);
    // An existing package is not overwritten.
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    QVERIFY(!window.export_package(*request).has_value());
    QCOMPARE(reports.size(), 1);

    // Windows, without kit: Linux paths reported as relative, PowerShell script.
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
    const auto readme = read(*win_dir / "README.txt");
    QVERIFY(readme.find("pki gen-csr") != std::string::npos);
    QVERIFY(readme.find("Points to note") != std::string::npos);

    // Incomplete kit refused.
    std::filesystem::remove(dir / "kit" / "chain.pem");
    request->out_dir = dir / "other";
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

    // Distant changes: the unchanged lines between them are elided.
    std::string before, after;
    for (int i = 0; i < 20; ++i) {
        before += "line " + std::to_string(i) + "\n";
        after += (i == 1 || i == 18 ? "changed " : "line ") + std::to_string(i) + "\n";
    }
    const auto spread = DiffDialog::render({{"/tmp/d.yaml", before, after}});
    QVERIFY(spread.contains("…"));
    QVERIFY(!spread.contains("line 10"));
}

namespace {

const std::string kPass = "test passphrase";

// Fake instance: generation with a signing request, like "pki gen-csr".
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
    QVERIFY(panel.create_authority(dir / "ca", "Test"));
    QVERIFY(panel.info().has_value());
    QCOMPARE(QString::fromStdString(panel.info()->root.subject), QString("CN=Test Root CA,O=Test"));

    // Signing a server and a client.
    SignOptions server{make_request(dir / "srv", "CN=relay.test,O=Test"), pki::Role::server, {"relay.test"}, 365,
                       false, dir / "kit-srv"};
    const auto s = panel.sign(server);
    QVERIFY2(s.has_value(), qPrintable(reports.join("\n")));
    QVERIFY(std::filesystem::exists(dir / "kit-srv" / "trust-issuer.pem"));
    SignOptions client{make_request(dir / "cli", "CN=branch.test,O=Test"), pki::Role::client, {}, 30, false,
                       dir / "kit-cli"};
    const auto c = panel.sign(client);
    QVERIFY(c.has_value());
    QCOMPARE(panel.inventory()->rowCount(), 2);
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "valid"), 2);

    // Same subject without renewal: refused; with renewal: the old one is replaced.
    client.csr = make_request(dir / "cli", "CN=branch.test,O=Test");
    QVERIFY(!panel.sign(client).has_value());
    QVERIFY(reports.last().contains("already assigned"));
    client.renew = true;
    client.out = dir / "kit-cli2";
    QVERIFY(panel.sign(client).has_value());
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "replaced"), 1);

    // Filters: the 30-day certificate expires soon.
    panel.set_filter(PkiPanel::expiring);
    QCOMPARE(panel.inventory()->rowCount(), 1);
    panel.set_filter(PkiPanel::retired);
    QCOMPARE(panel.inventory()->rowCount(), 1);
    panel.set_filter(PkiPanel::all);

    // Revocation: inventory, published CRLs and copy to deploy.
    QVERIFY(panel.revoke(s->serial, pki::RevocationReason::key_compromise, 30, dir / "deploy" / "crl.pem"));
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "revoked"), 1);
    QCOMPARE(panel.info()->revoked, size_t(1));
    QCOMPARE(panel.info()->crl_number, std::uint64_t(1));
    QVERIFY(read(dir / "deploy" / "crl.pem").find("BEGIN X509 CRL") != std::string::npos);
    QVERIFY(!panel.revoke(s->serial, pki::RevocationReason::unspecified, 30, std::nullopt));  // already revoked
    QVERIFY(panel.publish_crl(7, std::nullopt).has_value());
    QCOMPARE(panel.info()->crl_number, std::uint64_t(2));

    // Audit log: creation, 3 signatures, revocation, 2 CRLs.
    QCOMPARE(panel.audit()->rowCount(), 7);
    QVERIFY(panel.audit_status()->text().contains("intact"));

    // Another panel opens the same directory (command-line mini-CA).
    PkiPanel other;
    other.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    QVERIFY(other.open_authority(dir / "ca"));
    QCOMPARE(other.inventory()->rowCount(), 3);

    // Tampered log: reported.
    auto log = read(dir / "ca" / "audit.log");
    log.replace(log.find("sign"), 4, "s1gn");
    write(dir / "ca" / "audit.log", log);
    other.refresh();
    QVERIFY(other.audit_status()->text().contains("tampered"));
    QVERIFY(asked >= 6);
}

void AdminTest::pki_panel_refuses_wrong_passphrase_and_bad_directory() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    PkiPanel panel;
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    QVERIFY(!panel.open_authority(dir / "nothing"));
    QVERIFY(reports.last().contains("is not a tlsrelay CA directory"));
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return std::string("short"); };
    QVERIFY(!panel.create_authority(dir / "ca", "Test"));
    QVERIFY(reports.last().contains("too short"));
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };
    QVERIFY(panel.create_authority(dir / "ca", "Test"));
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return std::string("wrong passphrase!"); };
    const SignOptions options{make_request(dir / "srv", "CN=x.test"), pki::Role::server, {"x.test"}, 365, false,
                              dir / "kit"};
    QVERIFY(!panel.sign(options).has_value());
    QVERIFY(reports.last().contains("wrong passphrase"));
    QCOMPARE(panel.inventory()->rowCount(), 0);
    // Entry cancelled: nothing is done, no message.
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return std::nullopt; };
    const auto count = reports.size();
    QVERIFY(!panel.publish_crl(30, std::nullopt).has_value());
    QCOMPARE(reports.size(), count);
}

void AdminTest::sign_dialog_inspects_request() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    const auto csr = make_request(dir / "srv", "CN=relay.test,O=Test");
    SignDialog dialog(false, {}, pki::Role::server, nullptr);
    dialog.set_csr(to_qstring(csr));
    QVERIFY(dialog.request_description().contains("CN=relay.test,O=Test"));
    QVERIFY(!dialog.ready());  // server without SAN
    dialog.set_sans("relay.test, ip:192.0.2.10");
    QVERIFY(dialog.ready());
    const auto options = dialog.options();
    QCOMPARE(options.sans.size(), size_t(2));
    QCOMPARE(options.out, csr.parent_path() / "kit");
    dialog.set_sans("ip:999.1.1.1");
    QVERIFY(!dialog.ready());
    write(dir / "fake.csr", "not a request");
    dialog.set_csr(to_qstring(dir / "fake.csr"));
    QVERIFY(dialog.request_description().contains("refused"));
    QVERIFY(!dialog.ready());

    // Renewal: a subject different from the selected certificate is reported.
    SignDialog renew(true, "CN=other,O=Test", pki::Role::client, nullptr);
    renew.set_csr(to_qstring(make_request(dir / "cli", "CN=branch.test,O=Test")));
    QVERIFY(renew.options().renew);
    QVERIFY(renew.request_description().contains("warning"));
    QVERIFY(renew.ready());
}

void AdminTest::pki_root_change_preparation() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    PkiPanel panel;
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };
    QVERIFY(panel.create_authority(dir / "ca2", "Test"));
    QVERIFY(panel.create_authority(dir / "ca", "Test"));  // CA in service
    QVERIFY(!panel.prepare_root_change(dir / "ca", dir / "x"));
    QVERIFY(reports.last().contains("same root"));
    QVERIFY(panel.prepare_root_change(dir / "ca2", dir / "transition"));
    for (const char* f : {"server/trust-roots.pem", "server/trust-issuer.pem", "client/trust-roots.pem", "README.txt"}) {
        QVERIFY2(std::filesystem::exists(dir / "transition" / f), f);
    }
    QCOMPARE(panel.audit()->item(panel.audit()->rowCount() - 1, 2)->text(), QString("root-transition"));
}

namespace {

// Acts on the next modal window of type T that opens (QDialog::exec(),
// QFileDialog, QInputDialog, QMessageBox): the dialogs are driven as
// by a user. Each window is handled only once; without a window
// within 10 s, the wait stops (the test then fails on its checks).
template <class T>
void on_modal(std::function<void(T*)> action) {
    auto* timer = new QTimer;
    auto deadline = std::make_shared<QDeadlineTimer>(10000);
    QObject::connect(timer, &QTimer::timeout, timer, [timer, deadline, action] {
        auto* w = qobject_cast<T*>(QApplication::activeModalWidget());
        if (!w || w->property("handled").toBool()) {
            if (deadline->hasExpired()) timer->deleteLater();
            return;
        }
        w->setProperty("handled", true);
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
        // Choosing a directory: it becomes the picker's current directory.
        dialog->setDirectory(to_qstring(path));
        dialog->selectFile(QString());
    } else {
        // Name typed as by the user (selectFile does not replace a field that has focus).
        dialog->setDirectory(to_qstring(path.parent_path()));
        dialog->findChild<QLineEdit*>("fileNameEdit")->setText(to_qstring(path.filename()));
    }
    static_cast<QDialog*>(dialog)->accept();  // QFileDialog::accept: checks the chosen path
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
    QFAIL(qPrintable("missing action: " + text));
}

// CA created outside the panel (the tested panel keeps its default passphrase entry).
std::filesystem::path make_authority(const std::filesystem::path& dir) {
    pki::AuthorityOptions options;
    options.organization = "Test";
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

    // Invalid document: export refused before the dialog.
    window.new_document(Mode::server);
    trigger(&window, "Export deployment package…");
    QCOMPARE(reports.size(), 1);
    QVERIFY(reports.last().contains("before exporting"));

    write(dir / "branch.yaml", kServer);
    QVERIFY(window.open_file(dir / "branch.yaml"));
    std::filesystem::create_directories(dir / "kit");
    for (const char* f : {"cert.pem", "chain.pem", "trust-roots.pem", "trust-issuer.pem"}) write(dir / "kit" / f, "PEM\n");
    write(dir / "crl.pem", "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n");

    ExportRequest seen;
    QString warnings;
    bool info_shown = false;
    on_modal<ExportDialog>([&](ExportDialog* d) {
        // Without an output directory, "Export" does not close the dialog.
        press(d, QDialogButtonBox::Ok);
        QVERIFY(d->isVisible());
        d->findChild<QLineEdit*>("output")->setText(to_qstring(dir / "packages"));
        d->findChild<QComboBox*>("platform")->setCurrentIndex(1);  // Windows
        d->findChild<QLineEdit*>("kit")->setText(to_qstring(dir / "kit"));
        d->findChild<QLineEdit*>("crl")->setText(to_qstring(dir / "crl.pem"));
        seen = d->request();
        warnings = d->findChild<QLabel*>("warnings")->text();
        on_modal<QMessageBox>([&](QMessageBox* box) {
            info_shown = box->text().contains("README.txt");
            box->accept();
        });
        press(d, QDialogButtonBox::Ok);
    });
    trigger(&window, "Export deployment package…");
    QVERIFY2(reports.size() == 1, qPrintable(reports.join("\n")));
    QCOMPARE(seen.out_dir, dir / "packages");
    QVERIFY(seen.platform == TargetPlatform::windows_host);
    QCOMPARE(*seen.kit_dir, dir / "kit");
    QCOMPARE(*seen.crl_file, dir / "crl.pem");
    QVERIFY2(warnings.contains("credentials.pki_root"), qPrintable(warnings));  // Linux path for Windows
    QVERIFY(info_shown);
    QVERIFY(std::filesystem::exists(dir / "packages" / "branch" / "install.ps1"));

    // Cancellation: nothing is created.
    on_modal<ExportDialog>([&](ExportDialog* d) {
        d->findChild<QLineEdit*>("output")->setText(to_qstring(dir / "cancelled"));
        press(d, QDialogButtonBox::Cancel);
    });
    trigger(&window, "Export deployment package…");
    QVERIFY(!std::filesystem::exists(dir / "cancelled"));
}

void AdminTest::diff_dialog_is_shown_and_controls_saving() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    write(dir / "branch.yaml", kServer);
    write(dir / "whitelist.yaml", "peers:\n  - { name: lyon, ip: 192.0.2.10, ports: [mtls], subject: \"CN=lyon\" }\n");
    MainWindow window;  // default confirmation: the preview dialog
    window.show();
    window.report = [](const QString& m) { QFAIL(qPrintable(m)); };
    QVERIFY(window.open_file(dir / "branch.yaml"));

    // First save: both files are rewritten in normalized form.
    window.config_form()->set_value("limits.max_channels", "200");
    QString shown;
    on_modal<DiffDialog>([&](DiffDialog* d) {
        shown = d->findChild<QTextBrowser*>()->toPlainText();
        press(d, QDialogButtonBox::Save);
    });
    QVERIFY(window.save());
    QVERIFY2(shown.contains("branch.yaml") && shown.contains("max_channels: 200"), qPrintable(shown));
    QVERIFY(shown.contains("whitelist.yaml"));
    QVERIFY(std::filesystem::exists(dir / "branch.yaml.bak"));
    QCOMPARE(load_config_file(dir / "branch.yaml").config->limits.max_channels, 200u);

    // Only the configuration changes next: the preview shows only it.
    window.config_form()->set_value("limits.max_channels", "250");
    on_modal<DiffDialog>([&](DiffDialog* d) {
        shown = d->findChild<QTextBrowser*>()->toPlainText();
        press(d, QDialogButtonBox::Save);
    });
    QVERIFY(window.save());
    QVERIFY2(shown.contains("max_channels: 250") && !shown.contains("whitelist.yaml"), qPrintable(shown));
    QCOMPARE(load_config_file(dir / "branch.yaml").config->limits.max_channels, 250u);

    // Cancellation: nothing is written, the document stays modified.
    window.config_form()->set_value("limits.max_channels", "300");
    on_modal<DiffDialog>([&](DiffDialog* d) { press(d, QDialogButtonBox::Cancel); });
    QVERIFY(!window.save());
    QVERIFY(window.is_modified());
    QCOMPARE(load_config_file(dir / "branch.yaml").config->limits.max_channels, 250u);
}

void AdminTest::revoke_and_crl_dialogs() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    make_authority(dir / "ca");
    PkiPanel panel;
    QStringList reports, infos;
    panel.report = [&](const QString& m) { reports << m; };
    panel.inform = [&](const QString& m) { infos << m; };
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };
    QVERIFY(panel.open_authority(dir / "ca"));
    const auto a = panel.sign({make_request(dir / "a", "CN=a.test"), pki::Role::client, {}, 365, false, dir / "kit-a"});
    const auto b = panel.sign({make_request(dir / "b", "CN=b.test"), pki::Role::client, {}, 365, false, dir / "kit-b"});
    QVERIFY(a && b);

    // Revocation of a: reason, validity and CRL copy chosen in the dialog.
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
    button(&panel, "Revoke…")->click();
    QVERIFY2(reports.isEmpty(), qPrintable(reports.join("\n")));
    QVERIFY(infos.last().contains(QString::fromStdString(a->serial)));
    QCOMPARE(panel.inventory()->item(row_of(a->serial), PkiPanel::status_column)->text(), QString("revoked"));
    QVERIFY(panel.inventory()->item(row_of(a->serial), PkiPanel::revocation_column)->text().contains("keyCompromise"));
    QVERIFY(read(dir / "deploy" / "crl.pem").find("BEGIN X509 CRL") != std::string::npos);

    // CRL publication: 10 days, no copy.
    on_modal<QDialog>([&](QDialog* d) {
        d->findChild<QSpinBox*>()->setValue(10);
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Publish CRLs…")->click();
    QVERIFY2(infos.last().contains("CRL no. 2"), qPrintable(infos.last()));
    QCOMPARE(panel.info()->crl_number, std::uint64_t(2));

    // Revocation cancelled: b stays valid.
    panel.inventory()->selectRow(row_of(b->serial));
    on_modal<QDialog>([&](QDialog* d) { press(d, QDialogButtonBox::Cancel); });
    button(&panel, "Revoke…")->click();
    QCOMPARE(panel.inventory()->item(row_of(b->serial), PkiPanel::status_column)->text(), QString("valid"));
}

void AdminTest::root_change_dialog_creates_ca_and_prepares_files() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    make_authority(dir / "ca");
    std::filesystem::create_directories(dir / "new");
    PkiPanel panel;  // default passphrase entry: two input windows
    QStringList reports;
    panel.report = [&](const QString& m) { reports << m; };
    QVERIFY(panel.open_authority(dir / "ca"));

    // Creation of the new CA from the wizard; first attempt: different entries.
    auto create_new_ca = [&](QDialog* d, const QString& second) {
        on_modal<QFileDialog>([&, second](QFileDialog* f) {
            on_modal<QInputDialog>([&, second](QInputDialog* first) {
                on_modal<QInputDialog>([second](QInputDialog* confirm) { answer_text(confirm, second); });
                answer_text(first, QString::fromStdString(kPass));
            });
            choose_path(f, dir / "new");
        });
        button(d, "Create the new CA…")->click();
    };
    QString readme;
    on_modal<QDialog>([&](QDialog* d) {
        const auto edits = d->findChildren<QLineEdit*>();
        QCOMPARE(edits.size(), 2);
        press(d, QDialogButtonBox::Ok);  // empty fields: nothing
        create_new_ca(d, "another passphrase");
        QVERIFY(edits[0]->text().isEmpty());
        create_new_ca(d, QString::fromStdString(kPass));
        QCOMPARE(to_path(edits[0]->text()), dir / "new");
        edits[1]->setText(to_qstring(dir / "transition"));
        press(d, QDialogButtonBox::Ok);
        readme = d->findChild<QTextBrowser*>()->toPlainText();
        press(d, QDialogButtonBox::Close);
    });
    button(&panel, "Root change…")->click();
    QVERIFY(reports.contains("The two entries differ."));
    QVERIFY(std::filesystem::exists(dir / "new" / "root.cert.pem"));
    QVERIFY(pki::describe_authority(dir / "new").root.subject.find("O=Test") != std::string::npos);
    QVERIFY(std::filesystem::exists(dir / "transition" / "README.txt"));
    QVERIFY(!readme.isEmpty());
}

void AdminTest::sign_and_create_dialogs() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    std::filesystem::create_directories(dir / "ca");
    PkiPanel panel;
    QStringList reports, infos;
    panel.report = [&](const QString& m) { reports << m; };
    panel.inform = [&](const QString& m) { infos << m; };
    panel.ask_passphrase = [](const QString&, bool) -> std::optional<std::string> { return kPass; };

    // "Create a CA…": directory, organization.
    on_modal<QFileDialog>([&](QFileDialog* f) {
        on_modal<QInputDialog>([](QInputDialog* org) { answer_text(org, "Test"); });
        choose_path(f, dir / "ca");
    });
    button(&panel, "Create a CA…")->click();
    QVERIFY2(panel.info().has_value(), qPrintable(reports.join("\n")));
    QVERIFY(infos.last().contains("CA created"));

    // "Open a CA…" in another panel.
    PkiPanel other;
    other.report = [&](const QString& m) { reports << m; };
    on_modal<QFileDialog>([&](QFileDialog* f) { choose_path(f, dir / "ca"); });
    button(&other, "Open a CA…")->click();
    QCOMPARE(other.authority(), dir / "ca");

    // Signing: unreadable file reported, then a request with a SAN extension (ignored by the CA).
    std::string san_error;
    const auto sans = pki::parse_sans({"relay.test"}, san_error);
    QVERIFY(sans.has_value());
    const auto csr = pki::generate_csr(dir / "srv", "CN=relay.test,O=Test", *sans).csr;
    QString unreadable, description;
    on_modal<SignDialog>([&](SignDialog* d) {
        d->set_csr(to_qstring(dir / "absent.csr"));
        unreadable = d->request_description();
        d->set_csr(to_qstring(csr));
        d->set_sans("relay.test");
        d->set_out(to_qstring(dir / "kit"));
        description = d->request_description();
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Sign a request…")->click();
    QCOMPARE(unreadable, QString("unreadable file"));
    QVERIFY2(description.contains("requested extensions, ignored"), qPrintable(description));
    QVERIFY2(infos.last().contains("Certificate issued"), qPrintable(infos.last()));
    QVERIFY(std::filesystem::exists(dir / "kit" / "cert.pem"));

    // Renewal of the selected certificate: subject and role carried over.
    panel.inventory()->selectRow(0);
    QString expected;
    on_modal<SignDialog>([&](SignDialog* d) {
        QVERIFY(d->options().renew);
        QVERIFY(d->options().role == pki::Role::server);
        d->set_csr(to_qstring(pki::generate_csr(dir / "srv", "CN=relay.test,O=Test", {}).csr));
        d->set_sans("relay.test");
        d->set_out(to_qstring(dir / "kit2"));
        expected = d->request_description();
        press(d, QDialogButtonBox::Ok);
    });
    button(&panel, "Renew…")->click();
    QVERIFY(!expected.contains("warning"));  // same subject
    QCOMPARE(rows_with(panel.inventory(), PkiPanel::status_column, "replaced"), 1);
}

void AdminTest::main_window_navigation_and_close() {
    QTemporaryDir tmp;
    const auto dir = to_path(tmp.path());
    // Configuration with one error, one ignored key; whitelist with one error and one ignored key.
    write(dir / "branch.yaml", std::string(kServer) + "unknown: 1\n");
    {
        auto text = read(dir / "branch.yaml");
        text.replace(text.find("0.0.0.0:9003"), 12, "0.0.0.0:99999");
        write(dir / "branch.yaml", text);
    }
    write(dir / "whitelist.yaml", "peers:\n  - { name: a, ip: 10.0.0.1, ports: [plain], note: x }\n  - { name: b, ip: 300.0.0.1 }\n");
    MainWindow window;
    window.show();
    QStringList reports;
    window.report = [&](const QString& m) { reports << m; };
    window.confirm_save = [](const std::vector<FileChange>&) { return true; };
    QVERIFY(window.open_file(dir / "branch.yaml"));
    QVERIFY(window.error_count() >= 2);

    // Activating each error: matching tab and field.
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
        if (item->text().startsWith("Whitelist — peers[1]")) {
            whitelist_seen = tabs->currentIndex() == 1 && window.whitelist_editor()->table()->currentRow() == 1;
        }
    }
    QVERIFY2(config_seen && whitelist_seen, qPrintable(notes.join("\n")));
    QVERIFY2(notes.join("\n").contains("unknown ignored"), qPrintable(notes.join("\n")));
    QVERIFY2(notes.join("\n").contains("Whitelist: peers[0].note ignored"), qPrintable(notes.join("\n")));

    // About: versions of tlsrelay, OpenSSL and Qt.
    QString about;
    on_modal<QMessageBox>([&](QMessageBox* box) {
        about = box->text();
        box->accept();
    });
    trigger(&window, "About");
    QVERIFY2(about.contains("OpenSSL") && about.contains(qVersion()), qPrintable(about));

    // Reading and writing impossible.
    QVERIFY(!window.open_file(dir / "absent.yaml"));
    QVERIFY(reports.last().contains("Cannot read"));
    write(dir / "valid.yaml", kServer);
    write(dir / "whitelist.yaml", "peers: []\n");
    QVERIFY(window.open_file(dir / "valid.yaml"));
    write(dir / "file", "x");
    QVERIFY(!window.save_to(dir / "file" / "x.yaml"));
    QVERIFY(reports.last().contains("Cannot save"));

    // Open with pending changes: "No" keeps the document, then opening through the picker.
    window.config_form()->set_value("limits.max_channels", "10");
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::No)->click(); });
    trigger(&window, "Open…");
    QVERIFY(window.is_modified());
    window.config_form()->set_value("limits.max_channels", "");
    QVERIFY(window.save());
    on_modal<QFileDialog>([&](QFileDialog* f) { choose_path(f, dir / "branch.yaml"); });
    trigger(&window, "Open…");
    QCOMPARE(window.config_path(), dir / "branch.yaml");

    // Save As: path chosen in the picker.
    QVERIFY(window.open_file(dir / "valid.yaml"));
    on_modal<QFileDialog>([&](QFileDialog* f) { choose_path(f, dir / "copy.yaml"); });
    trigger(&window, "Save As…");
    QVERIFY(load_config_file(dir / "copy.yaml").config.has_value());

    // Closing with changes: Cancel, Discard, then Save.
    window.config_form()->set_value("limits.max_channels", "20");
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::Cancel)->click(); });
    QVERIFY(!window.close());
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::Save)->click(); });
    QVERIFY(window.close());
    QCOMPARE(load_config_file(dir / "copy.yaml").config->limits.max_channels, 20u);
    MainWindow second;
    second.show();
    QVERIFY(second.open_file(dir / "copy.yaml"));
    second.config_form()->set_value("limits.max_channels", "30");
    on_modal<QMessageBox>([](QMessageBox* box) { box->button(QMessageBox::Discard)->click(); });
    QVERIFY(second.close());
    QCOMPARE(load_config_file(dir / "copy.yaml").config->limits.max_channels, 20u);
    MainWindow third;  // no changes: closes without asking
    QVERIFY(third.close());
}

QTEST_MAIN(AdminTest)
#include "test_admin.moc"
