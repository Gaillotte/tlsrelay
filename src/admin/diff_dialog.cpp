#include "diff_dialog.hpp"

#include "tlsrelay/text_diff.hpp"

#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QLabel>
#include <QPushButton>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace tlsrelay::admin {

QString DiffDialog::render(const std::vector<FileChange>& changes) {
    QString html = "<html><body style=\"font-family: monospace; white-space: pre;\">";
    for (const auto& change : changes) {
        if (!change.changed()) continue;
        html += "<p><b>" + to_qstring(change.path).toHtmlEscaped() + "</b> — " +
                (change.before ? QObject::tr("modifié (copie de l'original : .bak)") : QObject::tr("créé")) + "</p>";
        const auto diff = diff_lines(change.before.value_or(""), change.after);
        // Trois lignes de contexte autour de chaque modification.
        std::vector<bool> keep(diff.size(), false);
        for (std::size_t k = 0; k < diff.size(); ++k) {
            if (diff[k].kind == DiffLine::Kind::same) continue;
            for (std::size_t x = k >= 3 ? k - 3 : 0; x < std::min(diff.size(), k + 4); ++x) keep[x] = true;
        }
        bool skipped = false;
        for (std::size_t k = 0; k < diff.size(); ++k) {
            if (!keep[k]) {
                skipped = true;
                continue;
            }
            if (skipped) html += "<div style=\"color: gray;\">…</div>";
            skipped = false;
            const auto text = QString::fromStdString(diff[k].text).toHtmlEscaped();
            switch (diff[k].kind) {
                case DiffLine::Kind::removed:
                    html += "<div style=\"background: #ffebee; color: #b71c1c;\">- " + text + "</div>";
                    break;
                case DiffLine::Kind::added:
                    html += "<div style=\"background: #e8f5e9; color: #1b5e20;\">+ " + text + "</div>";
                    break;
                case DiffLine::Kind::same: html += "<div>&nbsp; " + text + "</div>"; break;
            }
        }
    }
    return html + "</body></html>";
}

DiffDialog::DiffDialog(const std::vector<FileChange>& changes, QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Enregistrer les modifications"));
    resize(900, 600);
    auto* intro = new QLabel(tr("Vérifier les modifications avant de les écrire. Les commentaires des fichiers "
                                "d'origine ne sont pas conservés ; une copie de chaque fichier modifié est gardée "
                                "avec l'extension .bak."));
    intro->setWordWrap(true);
    auto* view = new QTextBrowser;
    view->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    view->setHtml(render(changes));
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Save)->setText(tr("Enregistrer"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Annuler"));
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    auto* layout = new QVBoxLayout(this);
    layout->addWidget(intro);
    layout->addWidget(view);
    layout->addWidget(buttons);
}

}  // namespace tlsrelay::admin
