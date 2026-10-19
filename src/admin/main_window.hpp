#pragma once

// Main window of tlsrelay-admin: an instance configuration and, in
// server mode, its whitelist; continuous validation, saving
// after a diff preview, export of the deployment package.

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
    // Exports the package (the dialog completes the request); std::nullopt on failure.
    std::optional<std::filesystem::path> export_package(const ExportRequest& request);
    // Export request prefilled with the current (valid) configuration.
    std::optional<ExportRequest> export_request();

    int error_count() const { return errors_; }
    bool is_modified() const { return modified_; }
    const std::filesystem::path& config_path() const { return config_path_; }
    std::filesystem::path whitelist_path() const;

    ConfigForm* config_form() const { return form_; }
    WhitelistEditor* whitelist_editor() const { return whitelist_; }
    QListWidget* issues() const { return issues_; }
    PkiPanel* pki_panel() const { return pki_; }

    // Replaceable interaction points (tests): save confirmation
    // (diff preview) and error message.
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
    std::vector<QString> load_notes_;  // items ignored when opening
    int errors_ = 0;
    bool modified_ = false;
    bool loading_ = false;
};

}  // namespace tlsrelay::admin
