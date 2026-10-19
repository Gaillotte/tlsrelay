#pragma once

// Whitelist editor of tlsrelay-admin: one row per peer. Validation
// goes through the service loader (Whitelist::load_string).

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

    // Loads a whitelist file (even invalid); returns the
    // ignored items (unknown keys, unknown ports).
    std::vector<std::string> load_yaml(const std::string& text);
    void set_peers(const std::vector<whitelist::PeerSpec>& peers);
    // Entered peers; no port box checked: default ports (SPEC §6).
    std::vector<whitelist::PeerSpec> peers() const;

    // Text to save (to_yaml).
    std::string yaml() const;
    // Validates like the service; highlights the cells in error.
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
