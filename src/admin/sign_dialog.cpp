#include "sign_dialog.hpp"

#include "document.hpp"
#include "tlsrelay/pki/request.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QVBoxLayout>

namespace tlsrelay::admin {

SignDialog::SignDialog(bool renew, const std::string& expected_subject, pki::Role role, QWidget* parent)
    : QDialog(parent),
      expected_subject_(expected_subject),
      csr_(new QLineEdit),
      request_(new QLabel),
      role_(new QComboBox),
      sans_(new QLineEdit),
      days_(new QSpinBox),
      renew_(new QCheckBox(tr("Renewal: the current certificate for this subject is marked replaced"))),
      out_(new QLineEdit) {
    setWindowTitle(renew ? tr("Renewal wizard") : tr("Sign a request"));
    resize(720, 420);
    role_->addItem(tr("server (serverAuth)"), static_cast<int>(pki::Role::server));
    role_->addItem(tr("client (clientAuth)"), static_cast<int>(pki::Role::client));
    role_->setCurrentIndex(role == pki::Role::server ? 0 : 1);
    sans_->setPlaceholderText(tr("relay.example, ip:192.0.2.10 (required for a server)"));
    days_->setRange(1, 3650);
    days_->setValue(365);
    days_->setSuffix(tr(" days"));
    renew_->setChecked(renew);
    request_->setWordWrap(true);
    request_->setTextFormat(Qt::PlainText);

    auto browse = [this](QLineEdit* edit, bool directory) {
        auto* row = new QHBoxLayout;
        auto* button = new QPushButton(tr("Browse…"));
        row->addWidget(edit);
        row->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, edit, directory] {
            const auto chosen = directory ? QFileDialog::getExistingDirectory(this, tr("Kit directory"))
                                          : QFileDialog::getOpenFileName(this, tr("Signing request"), {},
                                                                         tr("Request (*.csr *.pem);;All (*)"));
            if (!chosen.isEmpty()) edit->setText(chosen);
        });
        return row;
    };
    auto* form = new QFormLayout;
    form->addRow(tr("Request (request.csr)"), browse(csr_, false));
    form->addRow(tr("Content"), request_);
    form->addRow(tr("Role"), role_);
    form->addRow(tr("Names (SAN)"), sans_);
    form->addRow(tr("Validity"), days_);
    form->addRow(QString(), renew_);
    form->addRow(tr("Kit to produce"), browse(out_, true));

    auto* intro = new QLabel(
        renew ? tr("Renewal of an instance certificate, without interruption:\n"
                   "1. on the instance: tlsrelay pki gen-csr -c <conf> --subject \"<same subject>\" (new key);\n"
                   "2. here: sign the request (the current certificate is marked replaced);\n"
                   "3. on the instance: tlsrelay pki install -c <conf> --from <kit>, then pki activate.")
              : tr("The CA policy applies: ECDSA P-256 key, extensions set by the CA (those of the "
                   "request are ignored), unique subject except for renewal."));
    intro->setWordWrap(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    ok_ = buttons->button(QDialogButtonBox::Ok);
    ok_->setText(tr("Sign"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancel"));
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(csr_, &QLineEdit::textChanged, this, &SignDialog::inspect);
    connect(out_, &QLineEdit::textChanged, this, &SignDialog::inspect);
    connect(sans_, &QLineEdit::textChanged, this, &SignDialog::inspect);
    connect(role_, &QComboBox::currentIndexChanged, this, &SignDialog::inspect);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(intro);
    layout->addLayout(form);
    layout->addStretch();
    layout->addWidget(buttons);
    inspect();
}

void SignDialog::set_csr(const QString& path) { csr_->setText(path); }
void SignDialog::set_sans(const QString& sans) { sans_->setText(sans); }
void SignDialog::set_out(const QString& path) { out_->setText(path); }
QString SignDialog::request_description() const { return request_->text(); }

void SignDialog::inspect() {
    ready_ = false;
    const auto path = to_path(csr_->text());
    if (csr_->text().isEmpty()) {
        request_->setText(tr("(choose the request produced by \"tlsrelay pki gen-csr\" on the instance)"));
    } else if (const auto pem = read_text(path); !pem) {
        request_->setText(tr("unreadable file"));
    } else {
        try {
            const auto info = pki::inspect_request(*pem);
            if (out_->text().isEmpty()) {
                out_->setText(to_qstring(path.parent_path() / "kit"));  // triggers inspect() again
                return;
            }
            QString text = tr("subject: %1").arg(QString::fromStdString(info.subject));
            if (!info.requested_extensions.empty()) {
                QStringList names;
                for (const auto& e : info.requested_extensions) names << QString::fromStdString(e);
                text += "\n" + tr("requested extensions, ignored: %1").arg(names.join(", "));
            }
            bool ok = true;
            if (!expected_subject_.empty() && info.subject != expected_subject_) {
                text += "\n" + tr("warning: the certificate to renew has subject %1")
                                   .arg(QString::fromStdString(expected_subject_));
            }
            if (options().role == pki::Role::server && options().sans.empty()) {
                text += "\n" + tr("server certificate: give at least one name (SAN)");
                ok = false;
            }
            std::string error;
            if (!options().sans.empty() && !pki::parse_sans(options().sans, error)) {
                text += "\n" + tr("invalid SAN: %1").arg(QString::fromStdString(error));
                ok = false;
            }
            ready_ = ok && !out_->text().isEmpty();
            request_->setText(text);
        } catch (const std::exception& e) {
            request_->setText(tr("request refused: %1").arg(QString::fromStdString(e.what())));
        }
    }
    ok_->setEnabled(ready_);
}

SignOptions SignDialog::options() const {
    SignOptions o;
    o.csr = to_path(csr_->text());
    o.role = static_cast<pki::Role>(role_->currentData().toInt());
    for (const auto& item : sans_->text().split(QRegularExpression("[,;\\s]+"), Qt::SkipEmptyParts)) {
        o.sans.push_back(item.toStdString());
    }
    o.days = days_->value();
    o.renew = renew_->isChecked();
    o.out = to_path(out_->text());
    return o;
}

}  // namespace tlsrelay::admin
