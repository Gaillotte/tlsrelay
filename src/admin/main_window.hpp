#pragma once

// Fenêtre principale de tlsrelay-admin : une configuration d'instance et, en
// mode serveur, sa liste blanche ; validation permanente, enregistrement
// après aperçu des différences, export du paquet de déploiement.

#include "config_form.hpp"
#include "deployment.hpp"
#include "document.hpp"
#include "pki_panel.hpp"
#include "whitelist_editor.hpp"

#include <QMainWindow>

#include <filesystem>
#include <functional>
#include <optional>
#include <vector>

class QLabel;
class QListWidget;
class QTabWidget;

namespace tlsrelay::admin {

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

    void new_document(Mode mode);
    bool open_file(const std::filesystem::path& path);
    bool save();
    bool save_to(const std::filesystem::path& path);
    // Exporte le paquet (le dialogue complète la requête) ; std::nullopt en cas d'échec.
    std::optional<std::filesystem::path> export_package(const ExportRequest& request);
    // Requête d'export préremplie avec la configuration courante (valide).
    std::optional<ExportRequest> export_request();

    int error_count() const { return errors_; }
    bool is_modified() const { return modified_; }
    const std::filesystem::path& config_path() const { return config_path_; }
    std::filesystem::path whitelist_path() const;

    ConfigForm* config_form() const { return form_; }
    WhitelistEditor* whitelist_editor() const { return whitelist_; }
    QListWidget* issues() const { return issues_; }
    PkiPanel* pki_panel() const { return pki_; }

    // Points d'interaction remplaçables (tests) : confirmation de
    // l'enregistrement (aperçu des différences) et message d'erreur.
    std::function<bool(const std::vector<FileChange>&)> confirm_save;
    std::function<void(const QString&)> report;

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void revalidate();
    void set_modified(bool modified);
    void update_title();
    void build_menus();
    void choose_and_open();
    void choose_and_save();
    void choose_and_export();
    void go_to_issue(int row);

    ConfigForm* form_;
    WhitelistEditor* whitelist_;
    PkiPanel* pki_;
    QTabWidget* tabs_;
    QListWidget* issues_;
    QLabel* status_;
    std::filesystem::path config_path_;
    std::vector<QString> load_notes_;  // éléments ignorés à l'ouverture
    int errors_ = 0;
    bool modified_ = false;
    bool loading_ = false;
};

}  // namespace tlsrelay::admin
