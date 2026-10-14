#include "export_dialog.hpp"

#include "document.hpp"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace tlsrelay::admin {

ExportDialog::ExportDialog(ExportRequest request, QWidget* parent)
    : QDialog(parent),
      request_(std::move(request)),
      out_(new QLineEdit),
      platform_(new QComboBox),
      kit_(new QLineEdit),
      crl_(new QLineEdit),
      warnings_(new QLabel) {
    setWindowTitle(tr("Exporter le paquet de déploiement"));
    // Noms d'objet : repères stables pour les tests de l'interface.
    out_->setObjectName("sortie");
    platform_->setObjectName("plateforme");
    kit_->setObjectName("kit");
    crl_->setObjectName("crl");
    warnings_->setObjectName("avertissements");
    resize(700, 380);
    platform_->addItem(tr("Linux"), static_cast<int>(TargetPlatform::linux_host));
    platform_->addItem(tr("Windows"), static_cast<int>(TargetPlatform::windows_host));
    kit_->setPlaceholderText(tr("(facultatif) kit produit par la signature : cert.pem, chain.pem, trust-*.pem"));
    crl_->setPlaceholderText(tr("(facultatif) CRL publiées par l'AC"));
    warnings_->setWordWrap(true);
    warnings_->setStyleSheet("color: #e65100;");

    auto browse = [this](QLineEdit* edit, bool directory) {
        auto* row = new QHBoxLayout;
        auto* button = new QPushButton(tr("Parcourir…"));
        row->addWidget(edit);
        row->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, edit, directory] {
            const auto chosen = directory ? QFileDialog::getExistingDirectory(this, tr("Répertoire"), edit->text())
                                          : QFileDialog::getOpenFileName(this, tr("Fichier"), edit->text(),
                                                                         tr("CRL (*.pem *.crl);;Tous (*)"));
            if (!chosen.isEmpty()) edit->setText(chosen);
        });
        return row;
    };
    auto* form = new QFormLayout;
    form->addRow(tr("Répertoire de sortie"), browse(out_, true));
    form->addRow(tr("Machine cible"), platform_);
    form->addRow(tr("Kit PKI"), browse(kit_, true));
    form->addRow(tr("CRL"), browse(crl_, false));

    auto* intro = new QLabel(tr("Le paquet est créé dans un sous-répertoire au nom de l'instance (« %1 ») : "
                                "configuration, liste blanche, kit et CRL éventuels, script d'installation et "
                                "LISEZMOI.txt.")
                                 .arg(QString::fromStdString(request_.config.instance)));
    intro->setWordWrap(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Exporter"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Annuler"));
    connect(buttons, &QDialogButtonBox::accepted, this, [this] {
        if (!out_->text().isEmpty()) accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    for (auto* edit : {out_, kit_, crl_}) connect(edit, &QLineEdit::textChanged, this, &ExportDialog::refresh);
    connect(platform_, &QComboBox::currentIndexChanged, this, &ExportDialog::refresh);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(intro);
    layout->addLayout(form);
    layout->addWidget(warnings_);
    layout->addStretch();
    layout->addWidget(buttons);
    refresh();
}

void ExportDialog::refresh() {
    request_.out_dir = to_path(out_->text());
    request_.platform = static_cast<TargetPlatform>(platform_->currentData().toInt());
    request_.kit_dir = kit_->text().isEmpty() ? std::nullopt : std::optional(to_path(kit_->text()));
    request_.crl_file = crl_->text().isEmpty() ? std::nullopt : std::optional(to_path(crl_->text()));
    QString text;
    for (const auto& w : export_warnings(request_)) text += "• " + QString::fromStdString(w) + "\n";
    warnings_->setText(text.trimmed());
}

}  // namespace tlsrelay::admin
