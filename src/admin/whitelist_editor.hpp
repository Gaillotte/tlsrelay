#pragma once

// Éditeur de liste blanche de tlsrelay-admin : une ligne par pair. La
// validation passe par le chargeur du service (Whitelist::load_string).

#include "tlsrelay/whitelist.hpp"

#include <QWidget>

#include <string>
#include <vector>

class QTableWidget;
class QTableWidgetItem;

namespace tlsrelay::admin {

class WhitelistEditor : public QWidget {
    Q_OBJECT

public:
    enum Column { name = 0, ip, plain, tls, mtls, subject, column_count };

    explicit WhitelistEditor(QWidget* parent = nullptr);

    // Charge un fichier de liste blanche (même invalide) ; retourne les
    // éléments ignorés (clés inconnues, ports inconnus).
    std::vector<std::string> load_yaml(const std::string& text);
    void set_peers(const std::vector<whitelist::PeerSpec>& peers);
    // Pairs saisis ; aucune case de port cochée : ports par défaut (SPEC §6).
    std::vector<whitelist::PeerSpec> peers() const;

    // Texte à enregistrer (to_yaml).
    std::string yaml() const;
    // Valide comme le service ; met en évidence les cellules en erreur.
    whitelist::LoadResult validate();

    QTableWidget* table() const { return table_; }
    void add_peer();
    void remove_selected();
    void move_selected(int delta);

signals:
    void changed();

private:
    void set_row(int row, const whitelist::PeerSpec& peer);
    void clear_marks();
    void mark(int row, int column, const QString& message);

    QTableWidget* table_;
    bool loading_ = false;
};

}  // namespace tlsrelay::admin
