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
      renew_(new QCheckBox(tr("Renouvellement : le certificat en cours pour ce sujet est marqué remplacé"))),
      out_(new QLineEdit) {
    setWindowTitle(renew ? tr("Assistant de renouvellement") : tr("Signer une demande"));
    resize(720, 420);
    role_->addItem(tr("serveur (serverAuth)"), static_cast<int>(pki::Role::server));
    role_->addItem(tr("client (clientAuth)"), static_cast<int>(pki::Role::client));
    role_->setCurrentIndex(role == pki::Role::server ? 0 : 1);
    sans_->setPlaceholderText(tr("relais.exemple, ip:192.0.2.10 (obligatoire pour un serveur)"));
    days_->setRange(1, 3650);
    days_->setValue(365);
    days_->setSuffix(tr(" jours"));
    renew_->setChecked(renew);
    request_->setWordWrap(true);
    request_->setTextFormat(Qt::PlainText);

    auto browse = [this](QLineEdit* edit, bool directory) {
        auto* row = new QHBoxLayout;
        auto* button = new QPushButton(tr("Parcourir…"));
        row->addWidget(edit);
        row->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, edit, directory] {
            const auto chosen = directory ? QFileDialog::getExistingDirectory(this, tr("Répertoire du kit"))
                                          : QFileDialog::getOpenFileName(this, tr("Demande de signature"), {},
                                                                         tr("Demande (*.csr *.pem);;Tous (*)"));
            if (!chosen.isEmpty()) edit->setText(chosen);
        });
        return row;
    };
    auto* form = new QFormLayout;
    form->addRow(tr("Demande (request.csr)"), browse(csr_, false));
    form->addRow(tr("Contenu"), request_);
    form->addRow(tr("Rôle"), role_);
    form->addRow(tr("Noms (SAN)"), sans_);
    form->addRow(tr("Validité"), days_);
    form->addRow(QString(), renew_);
    form->addRow(tr("Kit à produire"), browse(out_, true));

    auto* intro = new QLabel(
        renew ? tr("Renouvellement d'un certificat d'instance, sans interruption :\n"
                   "1. sur l'instance : tlsrelay pki gen-csr -c <conf> --subject \"<même sujet>\" (nouvelle clé) ;\n"
                   "2. ici : signer la demande (le certificat en cours est marqué remplacé) ;\n"
                   "3. sur l'instance : tlsrelay pki install -c <conf> --from <kit>, puis pki activate.")
              : tr("La politique de l'AC s'applique : clé ECDSA P-256, extensions fixées par l'AC (celles de la "
                   "demande sont ignorées), sujet unique sauf renouvellement."));
    intro->setWordWrap(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    ok_ = buttons->button(QDialogButtonBox::Ok);
    ok_->setText(tr("Signer"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Annuler"));
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
        request_->setText(tr("(choisir la demande produite par « tlsrelay pki gen-csr » sur l'instance)"));
    } else if (const auto pem = read_text(path); !pem) {
        request_->setText(tr("fichier illisible"));
    } else {
        try {
            const auto info = pki::inspect_request(*pem);
            if (out_->text().isEmpty()) {
                out_->setText(to_qstring(path.parent_path() / "kit"));  // relance inspect()
                return;
            }
            QString text = tr("sujet : %1").arg(QString::fromStdString(info.subject));
            if (!info.requested_extensions.empty()) {
                QStringList names;
                for (const auto& e : info.requested_extensions) names << QString::fromStdString(e);
                text += "\n" + tr("extensions demandées, ignorées : %1").arg(names.join(", "));
            }
            bool ok = true;
            if (!expected_subject_.empty() && info.subject != expected_subject_) {
                text += "\n" + tr("attention : le certificat à renouveler a pour sujet %1")
                                   .arg(QString::fromStdString(expected_subject_));
            }
            if (options().role == pki::Role::server && options().sans.empty()) {
                text += "\n" + tr("certificat serveur : indiquer au moins un nom (SAN)");
                ok = false;
            }
            std::string error;
            if (!options().sans.empty() && !pki::parse_sans(options().sans, error)) {
                text += "\n" + tr("SAN invalide : %1").arg(QString::fromStdString(error));
                ok = false;
            }
            ready_ = ok && !out_->text().isEmpty();
            request_->setText(text);
        } catch (const std::exception& e) {
            request_->setText(tr("demande refusée : %1").arg(QString::fromStdString(e.what())));
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
