#include "main_window.hpp"

#include "diff_dialog.hpp"
#include "export_dialog.hpp"
#include "tlsrelay/openssl_info.hpp"
#include "tlsrelay/version.hpp"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QFileDialog>
#include <QKeySequence>
#include <QLabel>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>

namespace tlsrelay::admin {
namespace {

enum IssueRole { source_role = Qt::UserRole, path_role };
constexpr int kFromConfig = 0;
constexpr int kFromWhitelist = 1;

}  // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      form_(new ConfigForm),
      whitelist_(new WhitelistEditor),
      pki_(new PkiPanel),
      tabs_(new QTabWidget),
      issues_(new QListWidget),
      status_(new QLabel) {
    tabs_->addTab(form_, tr("Configuration"));
    tabs_->addTab(whitelist_, tr("Liste blanche"));
    tabs_->addTab(pki_, tr("PKI (autorité de certification)"));
    auto* split = new QSplitter(Qt::Vertical);
    split->addWidget(tabs_);
    split->addWidget(issues_);
    split->setStretchFactor(0, 4);
    split->setStretchFactor(1, 1);
    setCentralWidget(split);
    statusBar()->addWidget(status_, 1);
    resize(980, 760);

    confirm_save = [this](const std::vector<FileChange>& changes) {
        DiffDialog dialog(changes, this);
        return dialog.exec() == QDialog::Accepted;
    };
    report = [this](const QString& message) { QMessageBox::warning(this, tr("tlsrelay-admin"), message); };

    connect(form_, &ConfigForm::changed, this, [this] {
        if (loading_) return;
        set_modified(true);
        revalidate();
    });
    connect(whitelist_, &WhitelistEditor::changed, this, [this] {
        if (loading_) return;
        set_modified(true);
        revalidate();
    });
    // La liste des erreurs concerne la configuration et la liste blanche, pas la PKI.
    connect(tabs_, &QTabWidget::currentChanged, this, [this](int index) { issues_->setVisible(index != 2); });
    connect(issues_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) { go_to_issue(issues_->row(item)); });
    build_menus();
    new_document(Mode::server);
}

void MainWindow::build_menus() {
    // QAction créée puis connectée : même écriture de Qt 6.4 à 6.8 (sans surcharge dépréciée).
    auto action = [this](QMenu* menu, const QString& text, auto slot, const QKeySequence& key = {}) {
        QAction* a = menu->addAction(text);
        a->setShortcut(key);
        connect(a, &QAction::triggered, this, slot);
    };
    auto* file = menuBar()->addMenu(tr("&Fichier"));
    action(file, tr("Nouvelle configuration &serveur"), [this] { new_document(Mode::server); });
    action(file, tr("Nouvelle configuration &client"), [this] { new_document(Mode::client); }, QKeySequence::New);
    action(file, tr("&Ouvrir…"), [this] { choose_and_open(); }, QKeySequence::Open);
    action(file, tr("&Enregistrer"), [this] { save(); }, QKeySequence::Save);
    action(file, tr("Enregistrer &sous…"), [this] { choose_and_save(); }, QKeySequence::SaveAs);
    file->addSeparator();
    action(file, tr("E&xporter le paquet de déploiement…"), [this] { choose_and_export(); },
           QKeySequence(tr("Ctrl+E")));
    file->addSeparator();
    action(file, tr("&Quitter"), [this] { close(); }, QKeySequence::Quit);
    auto* help = menuBar()->addMenu(tr("&Aide"));
    help->addAction(tr("À &propos"), this, [this] {
        QMessageBox::about(this, tr("À propos de tlsrelay-admin"),
                           tr("<b>tlsrelay-admin</b> %1<br>Éditeur de configuration et de PKI de tlsrelay.<br><br>"
                              "%2<br>Qt %3, sous licence LGPLv3 (liaison dynamique).")
                               .arg(QString::fromStdString(std::string(kVersion)),
                                    QString::fromStdString(openssl_runtime_version()), qVersion()));
    });
}

void MainWindow::new_document(Mode mode) {
    loading_ = true;
    Config config;
    config.mode = mode;
    form_->load_yaml(to_yaml(config));
    whitelist_->set_peers({});
    loading_ = false;
    config_path_.clear();
    load_notes_.clear();
    set_modified(false);
    revalidate();
}

bool MainWindow::open_file(const std::filesystem::path& path) {
    const auto text = read_text(path);
    if (!text) {
        report(tr("Lecture impossible : %1").arg(to_qstring(path)));
        return false;
    }
    loading_ = true;
    load_notes_.clear();
    for (const auto& key : form_->load_yaml(*text)) {
        load_notes_.push_back(tr("Configuration : %1 ignoré (non modifiable dans l'éditeur, absent à "
                                 "l'enregistrement)").arg(QString::fromStdString(key)));
    }
    config_path_ = path;
    whitelist_->set_peers({});
    if (form_->mode() == Mode::server && !form_->value("whitelist.file").isEmpty()) {
        const auto wl_path = whitelist_path();
        if (const auto wl = read_text(wl_path)) {
            for (const auto& key : whitelist_->load_yaml(*wl)) {
                load_notes_.push_back(tr("Liste blanche : %1 ignoré").arg(QString::fromStdString(key)));
            }
        } else {
            load_notes_.push_back(tr("Liste blanche %1 absente : elle sera créée à l'enregistrement")
                                      .arg(to_qstring(wl_path)));
        }
    }
    loading_ = false;
    set_modified(false);
    revalidate();
    return true;
}

std::filesystem::path MainWindow::whitelist_path() const {
    const auto file = form_->value("whitelist.file").toStdString();
    if (config_path_.empty()) return to_path(QString::fromStdString(file));
    return resolve_from(config_path_, file);
}

void MainWindow::revalidate() {
    issues_->clear();
    errors_ = 0;
    auto add = [this](const QString& text, bool error, int source, const std::string& path) {
        auto* item = new QListWidgetItem(text, issues_);
        item->setForeground(error ? QColor(198, 40, 40) : QColor(230, 81, 0));
        item->setData(source_role, source);
        item->setData(path_role, QString::fromStdString(path));
        if (error) ++errors_;
    };
    const auto config = form_->validate();
    for (const auto& e : config.errors) {
        add(tr("Configuration — %1 : %2").arg(QString::fromStdString(e.path), QString::fromStdString(e.message)), true,
            kFromConfig, e.path);
    }
    for (const auto& w : config.warnings) {
        add(tr("Configuration — %1 : %2").arg(QString::fromStdString(w.path), QString::fromStdString(w.message)), false,
            kFromConfig, w.path);
    }
    const bool server = form_->mode() == Mode::server;
    tabs_->setTabEnabled(1, server);
    if (server) {
        const auto wl = whitelist_->validate();
        for (const auto& e : wl.errors) {
            add(tr("Liste blanche — %1 : %2").arg(QString::fromStdString(e.path), QString::fromStdString(e.message)),
                true, kFromWhitelist, e.path);
        }
        for (const auto& w : wl.warnings) {
            add(tr("Liste blanche — %1 : %2").arg(QString::fromStdString(w.path), QString::fromStdString(w.message)),
                false, kFromWhitelist, w.path);
        }
    }
    for (const auto& note : load_notes_) add(note, false, -1, {});
    status_->setText(errors_ == 0 ? tr("Configuration valide (règles du service tlsrelay)")
                                  : tr("%n erreur(s) à corriger", nullptr, errors_));
}

void MainWindow::go_to_issue(int row) {
    const auto* item = issues_->item(row);
    if (!item) return;
    const auto path = item->data(path_role).toString().toStdString();
    if (item->data(source_role).toInt() == kFromConfig) {
        tabs_->setCurrentIndex(0);
        if (auto* w = form_->widget_for(path)) w->setFocus();
    } else if (item->data(source_role).toInt() == kFromWhitelist) {
        tabs_->setCurrentIndex(1);
        const auto open = path.find('[');
        if (open != std::string::npos) {
            whitelist_->table()->setCurrentCell(QString::fromStdString(path.substr(open + 1)).section(']', 0, 0).toInt(),
                                                WhitelistEditor::name);
        }
    }
}

bool MainWindow::save() {
    if (config_path_.empty()) {
        choose_and_save();
        return !modified_;
    }
    return save_to(config_path_);
}

bool MainWindow::save_to(const std::filesystem::path& path) {
    revalidate();
    const auto config = load_config_string(form_->raw_yaml());
    const auto whitelist = whitelist_->validate();
    const bool server = config.config && config.config->mode == Mode::server;
    if (!config.config || (server && !whitelist.whitelist)) {
        report(tr("%n erreur(s) à corriger avant d'enregistrer (liste en bas de la fenêtre).", nullptr, errors_));
        return false;
    }
    std::vector<FileChange> changes;
    changes.push_back({path, read_text(path), to_yaml(*config.config, kWrittenBy)});
    if (server && config.config->whitelist) {
        const auto wl_path = resolve_from(path, config.config->whitelist->file);
        changes.push_back({wl_path, read_text(wl_path), whitelist::to_yaml(whitelist_->peers(), kWrittenBy)});
    }
    const bool any = std::any_of(changes.begin(), changes.end(), [](const FileChange& c) { return c.changed(); });
    if (any && !confirm_save(changes)) return false;
    try {
        for (const auto& change : changes) {
            if (change.changed()) write_with_backup(change.path, change.after);
        }
    } catch (const std::exception& e) {
        report(tr("Enregistrement impossible : %1").arg(QString::fromStdString(e.what())));
        return false;
    }
    config_path_ = path;
    load_notes_.clear();
    set_modified(false);
    revalidate();
    statusBar()->showMessage(any ? tr("Enregistré : %1").arg(to_qstring(path)) : tr("Aucune modification à enregistrer"),
                             5000);
    return true;
}

std::optional<ExportRequest> MainWindow::export_request() {
    revalidate();
    const auto config = load_config_string(form_->raw_yaml());
    const bool server = config.config && config.config->mode == Mode::server;
    if (!config.config || (server && !whitelist_->validate().whitelist)) {
        report(tr("%n erreur(s) à corriger avant d'exporter.", nullptr, errors_));
        return std::nullopt;
    }
    ExportRequest request;
    request.config = *config.config;
    request.config_text = to_yaml(*config.config, kWrittenBy);
    if (server) request.whitelist_text = whitelist::to_yaml(whitelist_->peers(), kWrittenBy);
    return request;
}

std::optional<std::filesystem::path> MainWindow::export_package(const ExportRequest& request) {
    try {
        auto dir = admin::export_package(request);
        statusBar()->showMessage(tr("Paquet exporté : %1").arg(to_qstring(dir)), 8000);
        return dir;
    } catch (const std::exception& e) {
        report(tr("Export impossible : %1").arg(QString::fromStdString(e.what())));
        return std::nullopt;
    }
}

void MainWindow::choose_and_open() {
    if (modified_ && QMessageBox::question(this, tr("tlsrelay-admin"),
                                           tr("Abandonner les modifications non enregistrées ?")) != QMessageBox::Yes) {
        return;
    }
    const auto file = QFileDialog::getOpenFileName(this, tr("Ouvrir une configuration"), {},
                                                   tr("Configuration tlsrelay (*.yaml *.yml);;Tous (*)"));
    if (!file.isEmpty()) open_file(to_path(file));
}

void MainWindow::choose_and_save() {
    const auto file = QFileDialog::getSaveFileName(this, tr("Enregistrer la configuration"),
                                                   to_qstring(config_path_), tr("Configuration tlsrelay (*.yaml)"));
    if (!file.isEmpty()) save_to(to_path(file));
}

void MainWindow::choose_and_export() {
    auto request = export_request();
    if (!request) return;
    ExportDialog dialog(*request, this);
    if (dialog.exec() != QDialog::Accepted) return;
    if (const auto dir = export_package(dialog.request())) {
        QMessageBox::information(this, tr("tlsrelay-admin"),
                                 tr("Paquet créé dans %1.\nSuivre LISEZMOI.txt sur la machine de l'instance.")
                                     .arg(to_qstring(*dir)));
    }
}

void MainWindow::set_modified(bool modified) {
    modified_ = modified;
    update_title();
}

void MainWindow::update_title() {
    const auto name = config_path_.empty() ? tr("nouvelle configuration") : to_qstring(config_path_);
    setWindowTitle(QString("%1%2 — tlsrelay-admin").arg(name, modified_ ? "*" : ""));
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (!modified_) {
        event->accept();
        return;
    }
    const auto answer = QMessageBox::question(this, tr("tlsrelay-admin"), tr("Enregistrer les modifications ?"),
                                              QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    if (answer == QMessageBox::Cancel || (answer == QMessageBox::Save && !save())) {
        event->ignore();
        return;
    }
    event->accept();
}

}  // namespace tlsrelay::admin
