#pragma once

// PKI module of tlsrelay-admin: opening or creating a mini-CA,
// inventory of issued certificates, signing of requests (and
// renewals), revocation and CRL publication, audit log,
// preparation of a root change. The operations are those of the
// command line ("tlsrelay ca …"), on the same CA directory.
//
// The CA passphrase is never kept: it is asked for at
// each operation that uses a CA key.

#include "tlsrelay/pki/authority.hpp"

#include <QWidget>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;

namespace tlsrelay::admin {

// Parameters of a signing operation ("Sign a request" dialog).
struct SignOptions {
    std::filesystem::path csr;
    pki::Role role = pki::Role::server;
    std::vector<std::string> sans;  // "dns:name", "ip:address" or bare value
    int days = 365;
    bool renew = false;
    std::filesystem::path out;  // kit directory
};

class PkiPanel : public QWidget {
    Q_OBJECT

public:
    enum InventoryColumn { serial_column = 0, role_column, status_column, not_after_column, subject_column,
                           revocation_column, inventory_columns };
    enum Filter { all = 0, in_service, revoked, expiring, retired };

    explicit PkiPanel(QWidget* parent = nullptr);

    bool open_authority(const std::filesystem::path& dir);
    bool create_authority(const std::filesystem::path& dir, const std::string& organization);
    std::optional<pki::IssuedCertificate> sign(const SignOptions& options);
    bool revoke(const std::string& serial, pki::RevocationReason reason, int crl_days,
                const std::optional<std::filesystem::path>& crl_copy);
    std::optional<pki::CrlInfo> publish_crl(int days, const std::optional<std::filesystem::path>& copy);
    bool prepare_root_change(const std::filesystem::path& new_dir, const std::filesystem::path& out);
    void refresh();
    void set_filter(Filter filter);

    const std::filesystem::path& authority() const { return dir_; }
    const std::optional<pki::AuthorityInfo>& info() const { return info_; }
    QTableWidget* inventory() const { return inventory_; }
    QTableWidget* audit() const { return audit_; }
    QLabel* audit_status() const { return audit_status_; }
    // Serial of the certificate selected in the inventory (empty if none).
    std::string selected_serial() const;

    // Replaceable interaction points (tests): passphrase (confirm:
    // typed twice, for a new CA), errors, information.
    std::function<std::optional<std::string>(const QString& prompt, bool confirm)> ask_passphrase;
    std::function<void(const QString&)> report;
    std::function<void(const QString&)> inform;

signals:
    // Another CA was opened (or created).
    void authority_changed();

private:
    void choose_and_open();
    void choose_and_create();
    void sign_dialog(bool renew);
    void revoke_dialog();
    void crl_dialog();
    void root_change_dialog();
    void update_buttons();

    std::filesystem::path dir_;
    std::optional<pki::AuthorityInfo> info_;
    std::vector<pki::IndexEntry> entries_;
    Filter filter_ = all;
    QLabel* title_;
    QLabel* summary_;
    QComboBox* filter_box_;
    QTableWidget* inventory_;
    QTableWidget* audit_;
    QLabel* audit_status_;
    std::vector<QPushButton*> actions_;
};

}  // namespace tlsrelay::admin
