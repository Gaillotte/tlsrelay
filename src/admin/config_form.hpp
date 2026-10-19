#pragma once

// Configuration form of tlsrelay-admin.
//
// The fields hold the text as typed, without interpretation: the form
// produces raw YAML (raw_yaml) read by the service loader
// (load_config_string). The editor's validation is therefore exactly the
// service's: same rules, same messages, same error paths.

#include "tlsrelay/config.hpp"

#include <QWidget>

#include <map>
#include <string>
#include <vector>

class QComboBox;
class QFormLayout;
class QGroupBox;
class QLineEdit;

namespace YAML {
class Node;
}

namespace tlsrelay::admin {

class ConfigForm : public QWidget {
    Q_OBJECT

public:
    explicit ConfigForm(QWidget* parent = nullptr);

    // Fills the fields from YAML (opened file, even invalid).
    // Returns the ignored keys: unknown ones, or values that are not of the
    // expected type (they will not be written back).
    std::vector<std::string> load_yaml(const std::string& text);

    // YAML matching the entered fields (empty fields omitted).
    std::string raw_yaml() const;

    // Validates the fields like the service; highlights the fields in error.
    LoadResult validate();

    // Selected mode.
    Mode mode() const;

    // Field associated with an error path ("ports.tls.listen"), or the
    // nearest section; nullptr if none.
    QWidget* widget_for(const std::string& path) const;

    // Access to the fields by YAML path (tests, default values).
    QString value(const std::string& path) const;
    void set_value(const std::string& path, const QString& value);
    void set_port_enabled(PortKind kind, bool enabled);
    bool port_enabled(PortKind kind) const;
    // Visible field (fields not applicable in the chosen mode are hidden
    // as long as they are empty).
    bool is_shown(const std::string& path) const;

signals:
    void changed();

private:
    struct Field {
        QWidget* widget = nullptr;  // QLineEdit or QComboBox
        QFormLayout* form = nullptr;
        enum class Scope { both, client, server, never } scope = Scope::both;
    };

    QLineEdit* add_line(QFormLayout* form, const std::string& path, const QString& label,
                        const QString& placeholder = {}, Field::Scope scope = Field::Scope::both);
    QComboBox* add_combo(QFormLayout* form, const std::string& path, const QString& label,
                         const std::vector<QString>& values, bool with_default = true,
                         Field::Scope scope = Field::Scope::both);
    void read_node(const YAML::Node& node, const std::string& path, std::vector<std::string>& ignored);
    void clear_marks();
    void mark(QWidget* widget, const QString& message);
    void update_visibility();

    std::map<std::string, Field> fields_;
    std::map<PortKind, QGroupBox*> ports_;
    std::map<std::string, QGroupBox*> sections_;
    std::vector<QWidget*> marked_;
    bool loading_ = false;
};

}  // namespace tlsrelay::admin
