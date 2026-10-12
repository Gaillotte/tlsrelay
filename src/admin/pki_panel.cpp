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

// Date de l'inventaire dans days jours (même format : comparaison de textes).
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
    return QString("<b>%1</b> : %2, jusqu'au %3<br><small>SHA-256 %4</small>")
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
        const auto first = QInputDialog::getText(this, tr("Phrase de passe de l'AC"), prompt, QLineEdit::Password, {}, &ok);
        if (!ok) return std::nullopt;
        if (confirm) {
            const auto second = QInputDialog::getText(this, tr("Phrase de passe de l'AC"), tr("Confirmer la phrase de passe"),
                                                      QLineEdit::Password, {}, &ok);
            if (!ok) return std::nullopt;
            if (second != first) {
                report(tr("Les deux saisies diffèrent."));
                return std::nullopt;
            }
        }
        return first.toStdString();
    };
    report = [this](const QString& m) { QMessageBox::warning(this, tr("PKI"), m); };
    inform = [this](const QString& m) { QMessageBox::information(this, tr("PKI"), m); };

    auto* open = new QPushButton(tr("Ouvrir une AC…"));
    auto* create = new QPushButton(tr("Créer une AC…"));
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
        {tr("Série"), tr("Rôle"), tr("État"), tr("Fin de validité"), tr("Sujet"), tr("Révocation")});
    for (int c : {serial_column, role_column, status_column, not_after_column, revocation_column}) {
        inventory_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    }
    inventory_->horizontalHeader()->setSectionResizeMode(subject_column, QHeaderView::Stretch);
    inventory_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    inventory_->setSelectionBehavior(QAbstractItemView::SelectRows);
    inventory_->setSelectionMode(QAbstractItemView::SingleSelection);
    filter_box_->addItems({tr("Tous les certificats"), tr("En service"), tr("Révoqués"), tr("Expirant dans 30 jours"),
                           tr("Remplacés ou expirés")});
    connect(filter_box_, &QComboBox::currentIndexChanged, this, [this](int i) { set_filter(static_cast<Filter>(i)); });
    connect(inventory_, &QTableWidget::itemSelectionChanged, this, &PkiPanel::update_buttons);

    audit_->setHorizontalHeaderLabels({tr("Date (UTC)"), tr("Opérateur"), tr("Opération"), tr("Détails")});
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
    pages->addTab(certs_page, tr("Certificats émis"));
    pages->addTab(audit_page, tr("Journal d'audit"));

    auto* buttons = new QHBoxLayout;
    const std::pair<QString, std::function<void()>> actions[] = {
        {tr("Signer une demande…"), [this] { sign_dialog(false); }},
        {tr("Renouveler…"), [this] { sign_dialog(true); }},
        {tr("Révoquer…"), [this] { revoke_dialog(); }},
        {tr("Publier les CRL…"), [this] { crl_dialog(); }},
        {tr("Changement de racine…"), [this] { root_change_dialog(); }},
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
        ask_passphrase(tr("Phrase de passe de la nouvelle AC (%1 caractères au moins)").arg(pki::kMinPassphrase), true);
    if (!passphrase) return false;
    try {
        pki::AuthorityOptions options;
        if (!organization.empty()) options.organization = organization;
        pki::init_authority(dir, *passphrase, options);
    } catch (const std::exception& e) {
        report(tr("Création impossible : %1").arg(q(e.what())));
        return false;
    }
    return open_authority(dir);
}

std::optional<pki::IssuedCertificate> PkiPanel::sign(const SignOptions& options) {
    const auto csr = read_text(options.csr);
    if (!csr) {
        report(tr("Lecture impossible : %1").arg(to_qstring(options.csr)));
        return std::nullopt;
    }
    std::string error;
    const auto sans = pki::parse_sans(options.sans, error);
    if (!sans) {
        report(q(error));
        return std::nullopt;
    }
    const auto passphrase = ask_passphrase(tr("Phrase de passe de l'AC"), false);
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
        report(tr("Signature refusée : %1").arg(q(e.what())));
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
    // La révocation ne prend effet qu'avec les CRL publiées et déployées.
    return publish_crl(crl_days, crl_copy).has_value();
}

std::optional<pki::CrlInfo> PkiPanel::publish_crl(int days, const std::optional<std::filesystem::path>& copy) {
    const auto passphrase = ask_passphrase(tr("Phrase de passe de l'AC (signature des CRL)"), false);
    if (!passphrase) return std::nullopt;
    try {
        auto crl = pki::publish_crl(dir_, *passphrase, days);
        if (copy) write_with_backup(*copy, crl.pem);
        refresh();
        return crl;
    } catch (const std::exception& e) {
        report(tr("Publication des CRL impossible : %1").arg(q(e.what())));
        refresh();
        return std::nullopt;
    }
}

bool PkiPanel::prepare_root_change(const std::filesystem::path& new_dir, const std::filesystem::path& out) {
    try {
        pki::write_root_transition(dir_, new_dir, out);
    } catch (const std::exception& e) {
        report(tr("Préparation impossible : %1").arg(q(e.what())));
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
    title_->setText(dir_.empty() ? tr("Aucune AC ouverte") : tr("AC : %1").arg(to_qstring(dir_)));
    if (info_) {
        const auto& i = *info_;
        QString crl = i.crl_number == 0 ? tr("aucune CRL publiée")
                                        : tr("CRL n° %1, prochaine mise à jour avant le %2").arg(i.crl_number).arg(q(i.crl_next_update));
        if (i.crl_number != 0 && pki::is_past(i.crl_next_update)) {
            crl = "<span style=\"color:#c62828\">" + crl + tr(" : périmée, à republier") + "</span>";
        } else if (i.crl_number != 0 && i.crl_next_update <= date_in_days(7)) {
            crl = "<span style=\"color:#e65100\">" + crl + tr(" : à republier bientôt") + "</span>";
        }
        summary_->setText(ca_line(tr("Racine"), i.root) + "<br>" + ca_line(tr("AC Serveurs"), i.servers) + "<br>" +
                          ca_line(tr("AC Clients"), i.clients) + "<br>" +
                          tr("%1 certificat(s) émis, %2 en service, %3 révoqué(s) ; %4")
                              .arg(i.issued).arg(i.valid).arg(i.revoked).arg(crl));
    } else if (dir_.empty()) {
        summary_->setText(tr("Ouvrir le répertoire d'une AC créée par « tlsrelay ca init » ou par l'éditeur, ou créer "
                             "une AC. Le répertoire et la phrase de passe restent sur le poste d'administration."));
    }

    // Journal d'audit.
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
            audit_status_->setText(tr("Journal altéré à la ligne %1 : %2").arg(*log.broken_line).arg(q(log.problem)));
            audit_status_->setStyleSheet("color: #c62828; font-weight: bold;");
        } else {
            audit_status_->setText(tr("%1 opération(s), chaîne d'empreintes intacte").arg(log.entries.size()));
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
        const bool active = e.status == "valide" && !expired;
        const bool keep = filter == all || (filter == in_service && active) || (filter == revoked && e.status == "révoqué") ||
                          (filter == expiring && active && e.not_after <= soon) ||
                          (filter == retired && (e.status == "remplacé" || (expired && e.status != "révoqué")));
        if (!keep) continue;
        const int row = inventory_->rowCount();
        inventory_->insertRow(row);
        const QString state = expired && e.status == "valide" ? tr("expiré") : q(e.status);
        const QString revocation = e.revoked_at.empty() ? QString() : q(e.revoked_at + " (" + e.reason + ")");
        const QString cells[] = {q(e.serial), e.role == "server" ? tr("serveur") : tr("client"), state, q(e.not_after),
                                 q(e.subject), revocation};
        for (int c = 0; c < inventory_columns; ++c) {
            auto* item = new QTableWidgetItem(cells[c]);
            if (e.status == "révoqué") item->setForeground(QColor(198, 40, 40));
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
    if (actions_.size() > 2) actions_[2]->setEnabled(open && !selected_serial().empty());  // Révoquer
}

void PkiPanel::choose_and_open() {
    const auto dir = QFileDialog::getExistingDirectory(this, tr("Répertoire de l'AC"));
    if (!dir.isEmpty()) open_authority(to_path(dir));
}

void PkiPanel::choose_and_create() {
    const auto dir = QFileDialog::getExistingDirectory(this, tr("Répertoire de la nouvelle AC (vide)"));
    if (dir.isEmpty()) return;
    bool ok = false;
    const auto org = QInputDialog::getText(this, tr("Nouvelle AC"), tr("Organisation (O) des certificats d'AC"),
                                           QLineEdit::Normal, "tlsrelay", &ok);
    if (ok && create_authority(to_path(dir), org.toStdString())) {
        inform(tr("AC créée : racine (P-384, 15 ans), AC Serveurs et AC Clients (5 ans). Sauvegarder le répertoire et "
                  "la phrase de passe hors ligne."));
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
        inform(tr("Certificat émis : série %1, %2, valable jusqu'au %3.\nKit à transmettre à l'instance : %4\n"
                  "(tlsrelay pki install -c <conf> --from <kit>, puis pki activate)")
                   .arg(q(issued->serial), q(issued->subject), q(issued->not_after), to_qstring(dialog.options().out)));
    }
}

namespace {

// Durée de validité des CRL et copie à déployer : champs communs aux dialogues.
struct CrlFields {
    QSpinBox* days;
    QLineEdit* copy;
};

CrlFields add_crl_fields(QFormLayout* form, QWidget* parent) {
    auto* days = new QSpinBox;
    days->setRange(1, 366);
    days->setValue(30);
    days->setSuffix(QObject::tr(" jours"));
    auto* copy = new QLineEdit;
    copy->setPlaceholderText(QObject::tr("(facultatif) fichier à déployer sur les instances : pki crl -c <conf> <fichier>"));
    auto* row = new QHBoxLayout;
    auto* browse = new QPushButton(QObject::tr("Parcourir…"));
    row->addWidget(copy);
    row->addWidget(browse);
    QObject::connect(browse, &QPushButton::clicked, parent, [parent, copy] {
        const auto f = QFileDialog::getSaveFileName(parent, QObject::tr("Copie des CRL"), "crl.pem", "PEM (*.pem)");
        if (!f.isEmpty()) copy->setText(f);
    });
    form->addRow(QObject::tr("Validité des CRL"), days);
    form->addRow(QObject::tr("Copie"), row);
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
    dialog.setWindowTitle(tr("Révoquer un certificat"));
    auto* form = new QFormLayout;
    form->addRow(tr("Certificat"), new QLabel(q(entry->serial + " — " + entry->subject)));
    auto* reason = new QComboBox;
    const std::pair<QString, pki::RevocationReason> reasons[] = {
        {tr("Clé compromise (keyCompromise)"), pki::RevocationReason::key_compromise},
        {tr("Instance retirée (cessationOfOperation)"), pki::RevocationReason::cessation_of_operation},
        {tr("Remplacé (superseded)"), pki::RevocationReason::superseded},
        {tr("Non précisé (unspecified)"), pki::RevocationReason::unspecified}};
    for (const auto& [label, value] : reasons) reason->addItem(label, static_cast<int>(value));
    form->addRow(tr("Motif"), reason);
    const auto crl = add_crl_fields(form, &dialog);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Révoquer et publier les CRL"));
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    auto* layout = new QVBoxLayout(&dialog);
    auto* warning = new QLabel(tr("La révocation est définitive. Elle prend effet sur chaque instance quand les CRL y sont "
                                  "installées (tlsrelay pki crl) : le certificat est alors refusé et les canaux qui "
                                  "l'utilisent sont fermés."));
    warning->setWordWrap(true);
    layout->addWidget(warning);
    layout->addLayout(form);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted) return;
    const auto serial_copy = entry->serial;
    if (revoke(serial_copy, static_cast<pki::RevocationReason>(reason->currentData().toInt()), crl.days->value(),
               optional_path(crl.copy))) {
        inform(tr("Certificat %1 révoqué et CRL publiées. Les installer sur chaque instance.").arg(q(serial_copy)));
    }
}

void PkiPanel::crl_dialog() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Publier les CRL"));
    auto* form = new QFormLayout;
    const auto crl = add_crl_fields(form, &dialog);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Publier"));
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    auto* layout = new QVBoxLayout(&dialog);
    auto* intro = new QLabel(tr("Les CRL des AC Serveurs et Clients sont à republier avant leur échéance, puis à "
                                "installer sur chaque instance."));
    intro->setWordWrap(true);
    layout->addWidget(intro);
    layout->addLayout(form);
    layout->addWidget(buttons);
    if (dialog.exec() != QDialog::Accepted) return;
    if (const auto info = publish_crl(crl.days->value(), optional_path(crl.copy))) {
        inform(tr("CRL n° %1 publiées (%2 certificat(s) révoqué(s)), valables jusqu'au %3.")
                   .arg(info->number).arg(info->revoked).arg(q(info->next_update)));
    }
}

void PkiPanel::root_change_dialog() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Assistant de changement de racine"));
    dialog.resize(760, 560);
    auto* intro = new QLabel(tr(
        "Le changement de racine se fait en trois étapes, chacune appliquée à toutes les instances avant la suivante "
        "(SPEC §7.5) :\n1. pré-confiance : les instances font confiance aux deux racines, avec un certificat de "
        "l'ancienne AC ;\n2. bascule : certificats de la nouvelle AC, toujours deux racines ;\n3. retrait : nouvelle "
        "racine seule.\nL'assistant prépare les fichiers de confiance et les commandes de chaque étape."));
    intro->setWordWrap(true);
    auto* new_dir = new QLineEdit;
    auto* out = new QLineEdit;
    auto* create = new QPushButton(tr("Créer la nouvelle AC…"));
    auto* pick = new QPushButton(tr("Parcourir…"));
    auto* pick_out = new QPushButton(tr("Parcourir…"));
    connect(pick, &QPushButton::clicked, &dialog, [&] {
        const auto d = QFileDialog::getExistingDirectory(&dialog, tr("Nouvelle AC"));
        if (!d.isEmpty()) new_dir->setText(d);
    });
    connect(pick_out, &QPushButton::clicked, &dialog, [&] {
        const auto d = QFileDialog::getExistingDirectory(&dialog, tr("Répertoire à produire"));
        if (!d.isEmpty()) out->setText(d);
    });
    connect(create, &QPushButton::clicked, &dialog, [&] {
        const auto d = QFileDialog::getExistingDirectory(&dialog, tr("Répertoire de la nouvelle AC (vide)"));
        if (d.isEmpty()) return;
        try {
            pki::AuthorityOptions options;
            const auto org = info_ ? info_->root.subject : std::string();
            const auto at = org.find("O=");
            if (at != std::string::npos) options.organization = org.substr(at + 2, org.find(',', at) - at - 2);
            const auto passphrase = ask_passphrase(tr("Phrase de passe de la nouvelle AC"), true);
            if (!passphrase) return;
            pki::init_authority(to_path(d), *passphrase, options);
            new_dir->setText(d);
        } catch (const std::exception& e) {
            report(tr("Création impossible : %1").arg(q(e.what())));
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
    form->addRow(tr("Nouvelle AC"), row1);
    form->addRow(tr("Fichiers à produire"), row2);
    auto* result = new QTextBrowser;
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Close);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Préparer"));
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fermer"));
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        if (new_dir->text().isEmpty() || out->text().isEmpty()) return;
        if (prepare_root_change(to_path(new_dir->text()), to_path(out->text()))) {
            result->setPlainText(q(read_text(to_path(out->text()) / "LISEZMOI.txt").value_or("")));
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
