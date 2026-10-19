#include "pki_panel.hpp"

#include "document.hpp"
#include "sign_dialog.hpp"
#include "tlsrelay/pki/audit.hpp"
#include "tlsrelay/pki/request.hpp"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <ctime>

namespace tlsrelay::admin {
namespace {

// Inventory date in `days` days (same format: text comparison).
std::string date_in_days(int days) {
    const std::time_t t = std::time(nullptr) + static_cast<std::time_t>(days) * 86400;
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[32];
    (void)std::strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%SZ", &tm);
    return buffer;
}

QString q(const std::string& text) { return QString::fromStdString(text); }

QString ca_line(const QString& name, const pki::CaCertificate& ca) {
    return QString("<b>%1</b>: %2, until %3<br><small>SHA-256 %4</small>")
        .arg(name, q(ca.subject).toHtmlEscaped(), q(ca.not_after), q(ca.fingerprint));
}

}  // namespace

PkiPanel::PkiPanel(QWidget* parent)
    : QWidget(parent),
      title_(new QLabel),
      summary_(new QLabel),
      filter_box_(new QComboBox),
      inventory_(new QTableWidget(0, inventory_columns)),
      audit_(new QTableWidget(0, 4)),
      audit_status_(new QLabel) {
    ask_passphrase = [this](const QString& prompt, bool confirm) -> std::optional<std::string> {
        bool ok = false;
        const auto first = QInputDialog::getText(this, tr("CA passphrase"), prompt, QLineEdit::Password, {}, &ok);
        if (!ok) return std::nullopt;
        if (confirm) {
            const auto second = QInputDialog::getText(this, tr("CA passphrase"), tr("Confirm the passphrase"),
                                                      QLineEdit::Password, {}, &ok);
            if (!ok) return std::nullopt;
            if (second != first) {
                report(tr("The two entries differ."));
                return std::nullopt;
            }
        }
        return first.toStdString();
    };
    report = [this](const QString& m) { QMessageBox::warning(this, tr("PKI"), m); };
    inform = [this](const QString& m) { QMessageBox::information(this, tr("PKI"), m); };

    auto* open = new QPushButton(tr("Open a CA…"));
    auto* create = new QPushButton(tr("Create a CA…"));
    connect(open, &QPushButton::clicked, this, &PkiPanel::choose_and_open);
    connect(create, &QPushButton::clicked, this, &PkiPanel::choose_and_create);
    auto* top = new QHBoxLayout;
    top->addWidget(title_, 1);
    top->addWidget(open);
    top->addWidget(create);
    summary_->setTextFormat(Qt::RichText);
    summary_->setWordWrap(true);
    summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    inventory_->setHorizontalHeaderLabels(
        {tr("Serial"), tr("Role"), tr("Status"), tr("Not after"), tr("Subject"), tr("Revocation")});
    for (int c : {serial_column, role_column, status_column, not_after_column, revocation_column}) {
        inventory_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    }
    inventory_->horizontalHeader()->setSectionResizeMode(subject_column, QHeaderView::Stretch);
    inventory_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    inventory_->setSelectionBehavior(QAbstractItemView::SelectRows);
    inventory_->setSelectionMode(QAbstractItemView::SingleSelection);
    filter_box_->addItems({tr("All certificates"), tr("In service"), tr("Revoked"), tr("Expiring within 30 days"),
                           tr("Replaced or expired")});
    connect(filter_box_, &QComboBox::currentIndexChanged, this, [this](int i) { set_filter(static_cast<Filter>(i)); });
    connect(inventory_, &QTableWidget::itemSelectionChanged, this, &PkiPanel::update_buttons);

    audit_->setHorizontalHeaderLabels({tr("Date (UTC)"), tr("Operator"), tr("Operation"), tr("Details")});
    for (int c : {0, 1, 2}) audit_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    audit_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    audit_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    auto* certs_page = new QWidget;
    auto* certs_layout = new QVBoxLayout(certs_page);
    certs_layout->addWidget(filter_box_);
    certs_layout->addWidget(inventory_);
    auto* audit_page = new QWidget;
    auto* audit_layout = new QVBoxLayout(audit_page);
    audit_layout->addWidget(audit_status_);
    audit_layout->addWidget(audit_);
    auto* pages = new QTabWidget;
    pages->addTab(certs_page, tr("Issued certificates"));
    pages->addTab(audit_page, tr("Audit log"));

    auto* buttons = new QHBoxLayout;
    const std::pair<QString, std::function<void()>> actions[] = {
        {tr("Sign a request…"), [this] { sign_dialog(false); }},
        {tr("Renew…"), [this] { sign_dialog(true); }},
        {tr("Revoke…"), [this] { revoke_dialog(); }},
        {tr("Publish CRLs…"), [this] { crl_dialog(); }},
        {tr("Root change…"), [this] { root_change_dialog(); }},
    };
    for (const auto& [text, slot] : actions) {
        auto* button = new QPushButton(text);
        connect(button, &QPushButton::clicked, this, slot);
        buttons->addWidget(button);
        actions_.push_back(button);
    }
    buttons->addStretch();

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(top);
    layout->addWidget(summary_);
    layout->addWidget(pages, 1);
    layout->addLayout(buttons);
    refresh();
}

bool PkiPanel::open_authority(const std::filesystem::path& dir) {
    try {
        (void)pki::describe_authority(dir);
    } catch (const std::exception& e) {
        report(q(e.what()));
        return false;
    }
    dir_ = dir;
    refresh();
    emit authority_changed();
    return true;
}

bool PkiPanel::create_authority(const std::filesystem::path& dir, const std::string& organization) {
    const auto passphrase =
        ask_passphrase(tr("Passphrase of the new CA (at least %1 characters)").arg(pki::kMinPassphrase), true);
    if (!passphrase) return false;
    try {
        pki::AuthorityOptions options;
        if (!organization.empty()) options.organization = organization;
        pki::init_authority(dir, *passphrase, options);
    } catch (const std::exception& e) {
        report(tr("Cannot create: %1").arg(q(e.what())));
        return false;
    }
    return open_authority(dir);
}

std::optional<pki::IssuedCertificate> PkiPanel::sign(const SignOptions& options) {
    const auto csr = read_text(options.csr);
    if (!csr) {
        report(tr("Cannot read: %1").arg(to_qstring(options.csr)));
        return std::nullopt;
    }
    std::string error;
    const auto sans = pki::parse_sans(options.sans, error);
    if (!sans) {
        report(q(error));
        return std::nullopt;
    }
    const auto passphrase = ask_passphrase(tr("CA passphrase"), false);
    if (!passphrase) return std::nullopt;
    try {
        pki::SignRequest request;
        request.role = options.role;
        request.csr_pem = *csr;
        request.sans = *sans;
        request.days = options.days;
        request.renew = options.renew;
        auto issued = pki::sign_request(dir_, *passphrase, request);
        pki::write_bundle(options.out, issued);
        refresh();
        return issued;
    } catch (const std::exception& e) {
        report(tr("Signing refused: %1").arg(q(e.what())));
        refresh();
        return std::nullopt;
    }
}

bool PkiPanel::revoke(const std::string& serial_text, pki::RevocationReason reason, int crl_days,
                      const std::optional<std::filesystem::path>& crl_copy) {
    try {
        pki::revoke_certificate(dir_, serial_text, reason);
    } catch (const std::exception& e) {
        report(q(e.what()));
        return false;
    }
    refresh();
    // Revocation only takes effect once the CRLs are published and deployed.
    return publish_crl(crl_days, crl_copy).has_value();
}

std::optional<pki::CrlInfo> PkiPanel::publish_crl(int days, const std::optional<std::filesystem::path>& copy) {
    const auto passphrase = ask_passphrase(tr("CA passphrase (CRL signing)"), false);
    if (!passphrase) return std::nullopt;
    try {
        auto crl = pki::publish_crl(dir_, *passphrase, days);
        if (copy) write_with_backup(*copy, crl.pem);
        refresh();
        return crl;
    } catch (const std::exception& e) {
        report(tr("Cannot publish CRLs: %1").arg(q(e.what())));
        refresh();
        return std::nullopt;
    }
}

bool PkiPanel::prepare_root_change(const std::filesystem::path& new_dir, const std::filesystem::path& out) {
    try {
        pki::write_root_transition(dir_, new_dir, out);
    } catch (const std::exception& e) {
        report(tr("Cannot prepare: %1").arg(q(e.what())));
        return false;
    }
    refresh();
    return true;
}

void PkiPanel::refresh() {
    info_.reset();
    entries_.clear();
    if (!dir_.empty()) {
        try {
            info_ = pki::describe_authority(dir_);
            entries_ = pki::list_issued(dir_);
        } catch (const std::exception& e) {
            summary_->setText(tr("<span style=\"color:#c62828\">%1</span>").arg(q(e.what()).toHtmlEscaped()));
        }
    }
    title_->setText(dir_.empty() ? tr("No CA open") : tr("CA: %1").arg(to_qstring(dir_)));
    if (info_) {
        const auto& i = *info_;
        QString crl = i.crl_number == 0 ? tr("no CRL published")
                                        : tr("CRL no. %1, next update before %2").arg(i.crl_number).arg(q(i.crl_next_update));
        if (i.crl_number != 0 && pki::is_past(i.crl_next_update)) {
            crl = "<span style=\"color:#c62828\">" + crl + tr(": outdated, republish") + "</span>";
        } else if (i.crl_number != 0 && i.crl_next_update <= date_in_days(7)) {
            crl = "<span style=\"color:#e65100\">" + crl + tr(": republish soon") + "</span>";
        }
        summary_->setText(ca_line(tr("Root"), i.root) + "<br>" + ca_line(tr("Servers CA"), i.servers) + "<br>" +
                          ca_line(tr("Clients CA"), i.clients) + "<br>" +
                          tr("%1 certificate(s) issued, %2 in service, %3 revoked; %4")
                              .arg(i.issued).arg(i.valid).arg(i.revoked).arg(crl));
    } else if (dir_.empty()) {
        summary_->setText(tr("Open the directory of a CA created by \"tlsrelay ca init\" or by the editor, or create "
                             "a CA. The directory and the passphrase stay on the administration workstation."));
    }

    // Audit log.
    audit_->setRowCount(0);
    audit_status_->clear();
    if (info_) {
        const auto log = pki::read_audit(dir_);
        audit_->setRowCount(static_cast<int>(log.entries.size()));
        for (std::size_t r = 0; r < log.entries.size(); ++r) {
            const auto& e = log.entries[r];
            const QString cells[] = {q(e.date), q(e.operator_name), q(e.operation), q(e.details)};
            for (int c = 0; c < 4; ++c) audit_->setItem(static_cast<int>(r), c, new QTableWidgetItem(cells[c]));
        }
        if (log.broken_line) {
            audit_status_->setText(tr("Log tampered with at line %1: %2").arg(*log.broken_line).arg(q(log.problem)));
            audit_status_->setStyleSheet("color: #c62828; font-weight: bold;");
        } else {
            audit_status_->setText(tr("%1 operation(s), hash chain intact").arg(log.entries.size()));
            audit_status_->setStyleSheet("color: #2e7d32;");
        }
    }
    set_filter(filter_);
}

void PkiPanel::set_filter(Filter filter) {
    filter_ = filter;
    if (filter_box_->currentIndex() != filter) filter_box_->setCurrentIndex(filter);
    const auto soon = date_in_days(30);
    inventory_->setRowCount(0);
    for (const auto& e : entries_) {
        const bool expired = pki::is_past(e.not_after);
        const bool active = e.status == "valid" && !expired;
        const bool keep = filter == all || (filter == in_service && active) || (filter == revoked && e.status == "revoked") ||
                          (filter == expiring && active && e.not_after <= soon) ||
                          (filter == retired && (e.status == "replaced" || (expired && e.status != "revoked")));
        if (!keep) continue;
        const int row = inventory_->rowCount();
        inventory_->insertRow(row);
        const QString state = expired && e.status == "valid" ? tr("expired") : q(e.status);
        const QString revocation = e.revoked_at.empty() ? QString() : q(e.revoked_at + " (" + e.reason + ")");
        const QString cells[] = {q(e.serial), e.role == "server" ? tr("server") : tr("client"), state, q(e.not_after),
                                 q(e.subject), revocation};
        for (int c = 0; c < inventory_columns; ++c) {
            auto* item = new QTableWidgetItem(cells[c]);
            if (e.status == "revoked") item->setForeground(QColor(198, 40, 40));
            else if (!active) item->setForeground(QColor(117, 117, 117));
            else if (e.not_after <= soon) item->setBackground(QColor(255, 224, 178));
            inventory_->setItem(row, c, item);
        }
    }
    update_buttons();
}

std::string PkiPanel::selected_serial() const {
    const auto rows = inventory_->selectionModel() ? inventory_->selectionModel()->selectedRows() : QModelIndexList();
    if (rows.isEmpty()) return {};
    return inventory_->item(rows.front().row(), serial_column)->text().toStdString();
}

void PkiPanel::update_buttons() {
    const bool open = info_.has_value();
    for (auto* b : actions_) b->setEnabled(open);
    if (actions_.size() > 2) actions_[2]->setEnabled(open && !selected_serial().empty());  // Revoke
}

void PkiPanel::choose_and_open() {
    const auto dir = QFileDialog::getExistingDirectory(this, tr("CA directory"));
    if (!dir.isEmpty()) open_authority(to_path(dir));
}

void PkiPanel::choose_and_create() {
    const auto dir = QFileDialog::getExistingDirectory(this, tr("Directory of the new CA (empty)"));
    if (dir.isEmpty()) return;
    bool ok = false;
    const auto org = QInputDialog::getText(this, tr("New CA"), tr("Organization (O) of the CA certificates"),
                                           QLineEdit::Normal, "tlsrelay", &ok);
    if (ok && create_authority(to_path(dir), org.toStdString())) {
        inform(tr("CA created: root (P-384, 15 years), Servers CA and Clients CA (5 years). Back up the directory and "
                  "the passphrase offline."));
    }
}

void PkiPanel::sign_dialog(bool renew) {
    std::string expected;
    pki::Role role = pki::Role::server;
    if (renew) {
        const auto chosen = selected_serial();
        for (const auto& e : entries_) {
            if (e.serial != chosen) continue;
            expected = e.subject;
            role = e.role == "client" ? pki::Role::client : pki::Role::server;
        }
    }
    SignDialog dialog(renew, expected, role, this);
    if (dialog.exec() != QDialog::Accepted) return;
    if (const auto issued = sign(dialog.options())) {
        inform(tr("Certificate issued: serial %1, %2, valid until %3.\nKit to send to the instance: %4\n"
                  "(tlsrelay pki install -c <conf> --from <kit>, then pki activate)")
                   .arg(q(issued->serial), q(issued->subject), q(issued->not_after), to_qstring(dialog.options().out)));
    }
}

namespace {

// CRL validity and copy to deploy: fields shared by the dialogs.
struct CrlFields {
    QSpinBox* days;
    QLineEdit* copy;
};

CrlFields add_crl_fields(QFormLayout* form, QWidget* parent) {
    auto* days = new QSpinBox;
    days->setRange(1, 366);
    days->setValue(30);
    days->setSuffix(QObject::tr(" days"));
    auto* copy = new QLineEdit;
    copy->setPlaceholderText(QObject::tr("(optional) file to deploy on the instances: pki crl -c <conf> <file>"));
    auto* row = new QHBoxLayout;
    auto* browse = new QPushButton(QObject::tr("Browse…"));
    row->addWidget(copy);
    row->addWidget(browse);
    QObject::connect(browse, &QPushButton::clicked, parent, [parent, copy] {
        const auto f = QFileDialog::getSaveFileName(parent, QObject::tr("CRL copy"), "crl.pem", "PEM (*.pem)");
        if (!f.isEmpty()) copy->setText(f);
    });
    form->addRow(QObject::tr("CRL validity"), days);
    form->addRow(QObject::tr("Copy"), row);
    return {days, copy};
}

std::optional<std::filesystem::path> optional_path(const QLineEdit* edit) {
    if (edit->text().isEmpty()) return std::nullopt;
    return to_path(edit->text());
}

}  // namespace

void PkiPanel::revoke_dialog() {
    const auto chosen = selected_serial();
    const pki::IndexEntry* entry = nullptr;
    for (const auto& e : entries_) {
        if (e.serial == chosen) entry = &e;
    }
    if (!entry) return;
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Revoke a certificate"));
    auto* form = new QFormLayout;
    form->addRow(tr("Certificate"), new QLabel(q(entry->serial + " — " + entry->subject)));
    auto* reason = new QComboBox;
    const std::pair<QString, pki::RevocationReason> reasons[] = {
        {tr("Key compromised (keyCompromise)"), pki::RevocationReason::key_compromise},
        {tr("Instance retired (cessationOfOperation)"), pki::RevocationReason::cessation_of_operation},
        {tr("Replaced (superseded)"), pki::RevocationReason::superseded},
        {tr("Unspecified (unspecified)"), pki::RevocationReason::unspecified}};
    for (const auto& [label, value] : reasons) reason->addItem(label, static_cast<int>(value));
    form->addRow(tr("Reason"), reason);
    const auto crl = add_crl_fields(form, &dialog);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Revoke and publish CRLs"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancel"));
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    auto* layout = new QVBoxLayout(&dialog);
    auto* warning = new QLabel(tr("Revocation is final. It takes effect on each instance when the CRLs are "
                                  "installed there (tlsrelay pki crl): the certificate is then refused and the channels "
                                  "that use it are closed."));
    warning->setWordWrap(true);
    layout->addWidget(warning);
    layout->addLayout(form);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted) return;
    const auto serial_copy = entry->serial;
    if (revoke(serial_copy, static_cast<pki::RevocationReason>(reason->currentData().toInt()), crl.days->value(),
               optional_path(crl.copy))) {
        inform(tr("Certificate %1 revoked and CRLs published. Install them on each instance.").arg(q(serial_copy)));
    }
}

void PkiPanel::crl_dialog() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Publish CRLs"));
    auto* form = new QFormLayout;
    const auto crl = add_crl_fields(form, &dialog);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Publish"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancel"));
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    auto* layout = new QVBoxLayout(&dialog);
    auto* intro = new QLabel(tr("The CRLs of the Servers and Clients CAs must be republished before they expire, then "
                                "installed on each instance."));
    intro->setWordWrap(true);
    layout->addWidget(intro);
    layout->addLayout(form);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted) return;
    if (const auto info = publish_crl(crl.days->value(), optional_path(crl.copy))) {
        inform(tr("CRL no. %1 published (%2 certificate(s) revoked), valid until %3.")
                   .arg(info->number).arg(info->revoked).arg(q(info->next_update)));
    }
}

void PkiPanel::root_change_dialog() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Root change wizard"));
    dialog.resize(760, 560);
    auto* intro = new QLabel(tr(
        "A root change takes three steps, each applied to all instances before the next one "
        "(SPEC §7.5):\n1. pre-trust: the instances trust both roots, with a certificate from "
        "the old CA;\n2. switch: certificates from the new CA, still two roots;\n3. retire: new "
        "root only.\nThe wizard prepares the trust files and the commands for each step."));
    intro->setWordWrap(true);
    auto* new_dir = new QLineEdit;
    auto* out = new QLineEdit;
    auto* create = new QPushButton(tr("Create the new CA…"));
    auto* pick = new QPushButton(tr("Browse…"));
    auto* pick_out = new QPushButton(tr("Browse…"));
    connect(pick, &QPushButton::clicked, &dialog, [&] {
        const auto d = QFileDialog::getExistingDirectory(&dialog, tr("New CA"));
        if (!d.isEmpty()) new_dir->setText(d);
    });
    connect(pick_out, &QPushButton::clicked, &dialog, [&] {
        const auto d = QFileDialog::getExistingDirectory(&dialog, tr("Output directory"));
        if (!d.isEmpty()) out->setText(d);
    });
    connect(create, &QPushButton::clicked, &dialog, [&] {
        const auto d = QFileDialog::getExistingDirectory(&dialog, tr("Directory of the new CA (empty)"));
        if (d.isEmpty()) return;
        try {
            pki::AuthorityOptions options;
            const auto org = info_ ? info_->root.subject : std::string();
            const auto at = org.find("O=");
            if (at != std::string::npos) options.organization = org.substr(at + 2, org.find(',', at) - at - 2);
            const auto passphrase = ask_passphrase(tr("Passphrase of the new CA"), true);
            if (!passphrase) return;
            pki::init_authority(to_path(d), *passphrase, options);
            new_dir->setText(d);
        } catch (const std::exception& e) {
            report(tr("Cannot create: %1").arg(q(e.what())));
        }
    });
    auto* form = new QFormLayout;
    auto* row1 = new QHBoxLayout;
    row1->addWidget(new_dir);
    row1->addWidget(pick);
    row1->addWidget(create);
    auto* row2 = new QHBoxLayout;
    row2->addWidget(out);
    row2->addWidget(pick_out);
    form->addRow(tr("New CA"), row1);
    form->addRow(tr("Files to produce"), row2);
    auto* result = new QTextBrowser;
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Close);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Prepare"));
    buttons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        if (new_dir->text().isEmpty() || out->text().isEmpty()) return;
        if (prepare_root_change(to_path(new_dir->text()), to_path(out->text()))) {
            result->setPlainText(q(read_text(to_path(out->text()) / "README.txt").value_or("")));
        }
    });
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(intro);
    layout->addLayout(form);
    layout->addWidget(result, 1);
    layout->addWidget(buttons);
    dialog.exec();
}

}  // namespace tlsrelay::admin
