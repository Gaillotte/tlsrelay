#pragma once

// Formulaire de configuration de tlsrelay-admin.
//
// Les champs contiennent le texte saisi, sans interprétation : le formulaire
// produit un YAML brut (raw_yaml) que lit le chargeur du service
// (load_config_string). La validation de l'éditeur est donc exactement celle
// du service : mêmes règles, mêmes messages, mêmes chemins d'erreur.

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

    // Remplit les champs à partir d'un YAML (fichier ouvert, même invalide).
    // Retourne les clés ignorées : inconnues, ou valeurs qui ne sont pas du
    // type attendu (elles ne seront pas réécrites).
    std::vector<std::string> load_yaml(const std::string& text);

    // YAML correspondant aux champs saisis (champs vides omis).
    std::string raw_yaml() const;

    // Valide les champs comme le service ; met en évidence les champs en erreur.
    LoadResult validate();

    // Mode sélectionné.
    Mode mode() const;

    // Champ associé à un chemin d'erreur (« ports.tls.listen »), ou à la
    // section la plus proche ; nullptr si aucun.
    QWidget* widget_for(const std::string& path) const;

    // Accès aux champs par chemin YAML (tests, valeurs par défaut).
    QString value(const std::string& path) const;
    void set_value(const std::string& path, const QString& value);
    void set_port_enabled(PortKind kind, bool enabled);
    bool port_enabled(PortKind kind) const;
    // Champ visible (les champs sans objet dans le mode choisi sont masqués
    // tant qu'ils sont vides).
    bool is_shown(const std::string& path) const;

signals:
    void changed();

private:
    struct Field {
        QWidget* widget = nullptr;  // QLineEdit ou QComboBox
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
