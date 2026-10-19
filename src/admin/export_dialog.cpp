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
    setWindowTitle(tr("Export deployment package"));
    // Object names: stable handles for the UI tests.
    out_->setObjectName("output");
    platform_->setObjectName("platform");
    kit_->setObjectName("kit");
    crl_->setObjectName("crl");
    warnings_->setObjectName("warnings");
    resize(700, 380);
    platform_->addItem(tr("Linux"), static_cast<int>(TargetPlatform::linux_host));
    platform_->addItem(tr("Windows"), static_cast<int>(TargetPlatform::windows_host));
    kit_->setPlaceholderText(tr("(optional) kit produced by signing: cert.pem, chain.pem, trust-*.pem"));
    crl_->setPlaceholderText(tr("(optional) CRLs published by the CA"));
    warnings_->setWordWrap(true);
    warnings_->setStyleSheet("color: #e65100;");

    auto browse = [this](QLineEdit* edit, bool directory) {
        auto* row = new QHBoxLayout;
        auto* button = new QPushButton(tr("Browse…"));
        row->addWidget(edit);
        row->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this, edit, directory] {
            const auto chosen = directory ? QFileDialog::getExistingDirectory(this, tr("Directory"), edit->text())
                                          : QFileDialog::getOpenFileName(this, tr("File"), edit->text(),
                                                                         tr("CRL (*.pem *.crl);;All (*)"));
            if (!chosen.isEmpty()) edit->setText(chosen);
        });
        return row;
    };
    auto* form = new QFormLayout;
    form->addRow(tr("Output directory"), browse(out_, true));
    form->addRow(tr("Target machine"), platform_);
    form->addRow(tr("PKI kit"), browse(kit_, true));
    form->addRow(tr("CRL"), browse(crl_, false));

    auto* intro = new QLabel(tr("The package is created in a subdirectory named after the instance (\"%1\"): "
                                "configuration, whitelist, optional kit and CRLs, installation script and "
                                "README.txt.")
                                 .arg(QString::fromStdString(request_.config.instance)));
    intro->setWordWrap(true);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Export"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancel"));
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
