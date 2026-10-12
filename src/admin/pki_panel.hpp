#pragma once

// Module PKI de tlsrelay-admin : reprise ou création d'une mini-AC,
// inventaire des certificats émis, signature des demandes (et
// renouvellements), révocation et publication des CRL, journal d'audit,
// préparation d'un changement de racine. Les opérations sont celles de la
// ligne de commande (« tlsrelay ca … »), sur le même répertoire d'AC.
//
// La phrase de passe de l'AC n'est jamais conservée : elle est demandée à
// chaque opération qui utilise une clé d'AC.

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

// Paramètres d'une signature (dialogue « Signer une demande »).
struct SignOptions {
    std::filesystem::path csr;
    pki::Role role = pki::Role::server;
    std::vector<std::string> sans;  // « dns:nom », « ip:adresse » ou valeur seule
    int days = 365;
    bool renew = false;
    std::filesystem::path out;  // répertoire du kit
};

class PkiPanel : public QWidget {
    Q_OBJECT

public:
    enum InventoryColumn { serial = 0, role, status, not_after, subject, revocation, inventory_columns };
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
    // Série du certificat sélectionné dans l'inventaire (vide si aucun).
    std::string selected_serial() const;

    // Points d'interaction remplaçables (tests) : phrase de passe (confirm :
    // saisie en double, pour une nouvelle AC), erreurs, informations.
    std::function<std::optional<std::string>(const QString& prompt, bool confirm)> ask_passphrase;
    std::function<void(const QString&)> report;
    std::function<void(const QString&)> inform;

signals:
    // Une autre AC a été ouverte (ou créée).
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
