#pragma once

// Signature d'une demande (CSR) par la mini-AC, ou renouvellement : la
// demande est examinée dès qu'elle est choisie (sujet, preuve de possession,
// clé P-256), comme le fera la signature.

#include "pki_panel.hpp"

#include <QDialog>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;

namespace tlsrelay::admin {

class SignDialog : public QDialog {
    Q_OBJECT

public:
    // renew : assistant de renouvellement ; expected_subject : sujet du
    // certificat à renouveler (sélection de l'inventaire), vide sinon.
    SignDialog(bool renew, const std::string& expected_subject, pki::Role role, QWidget* parent = nullptr);

    SignOptions options() const;
    // Demande lisible et conforme, champs obligatoires remplis.
    bool ready() const { return ready_; }
    QString request_description() const;

    void set_csr(const QString& path);
    void set_sans(const QString& sans);
    void set_out(const QString& path);

private:
    void inspect();

    std::string expected_subject_;
    bool ready_ = false;
    QLineEdit* csr_;
    QLabel* request_;
    QComboBox* role_;
    QLineEdit* sans_;
    QSpinBox* days_;
    QCheckBox* renew_;
    QLineEdit* out_;
    QPushButton* ok_;
};

}  // namespace tlsrelay::admin
