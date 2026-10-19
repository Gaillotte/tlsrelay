#pragma once

// Signing of a request (CSR) by the mini-CA, or renewal: the
// request is inspected as soon as it is chosen (subject, proof of possession,
// P-256 key), as the signing will do.

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
    // renew: renewal wizard; expected_subject: subject of the
    // certificate to renew (inventory selection), empty otherwise.
    SignDialog(bool renew, const std::string& expected_subject, pki::Role role, QWidget* parent = nullptr);

    SignOptions options() const;
    // Request readable and compliant, required fields filled in.
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
