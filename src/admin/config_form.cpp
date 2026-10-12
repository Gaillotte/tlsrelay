#include "config_form.hpp"

#include "tlsrelay/units.hpp"

#include <yaml-cpp/yaml.h>

#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QScrollArea>
#include <QStyle>
#include <QVBoxLayout>

#include <tuple>

namespace tlsrelay::admin {
namespace {

// Sections du fichier : chemins qui contiennent d'autres clés.
const std::vector<std::string> kContainers = {"",       "logging", "logging.categories", "credentials", "limits",
                                              "ports",  "ports.plain", "ports.tls", "ports.mtls",
                                              "destination", "whitelist", "admin"};

std::vector<std::string> split_path(const std::string& path) {
    std::vector<std::string> keys;
    std::size_t start = 0;
    for (;;) {
        const auto dot = path.find('.', start);
        keys.push_back(path.substr(start, dot - start));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return keys;
}

std::string join(const std::string& path, const std::string& key) { return path.empty() ? key : path + "." + key; }

// Affecte une valeur à un chemin, en créant les sections intermédiaires.
void put(YAML::Node node, const std::vector<std::string>& keys, std::size_t i, const YAML::Node& value) {
    if (i + 1 == keys.size()) {
        node[keys[i]] = value;
        return;
    }
    YAML::Node child = node[keys[i]];
    put(child, keys, i + 1, value);
}

const std::vector<QString> kLevels = {"error", "info", "debug", "trace"};

}  // namespace

ConfigForm::ConfigForm(QWidget* parent) : QWidget(parent) {
    setStyleSheet(
        "QLineEdit[invalid=\"true\"], QComboBox[invalid=\"true\"] { border: 1px solid #c62828; }"
        "QGroupBox[invalid=\"true\"] { color: #c62828; }");
    auto* content = new QWidget;
    auto* column = new QVBoxLayout(content);

    auto section = [&](const std::string& path, const QString& title) {
        auto* box = new QGroupBox(title);
        auto* form = new QFormLayout(box);
        form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        column->addWidget(box);
        sections_[path] = box;
        return form;
    };

    const Limits limits;
    const Destination destination;
    const Credentials credentials;

    auto* general = section("", tr("Général"));
    add_combo(general, "mode", tr("Mode"), {"client", "server"}, false);
    add_line(general, "instance", tr("Instance"), "default");

    auto* ports_box = new QGroupBox(tr("Ports"));
    auto* ports_layout = new QVBoxLayout(ports_box);
    sections_["ports"] = ports_box;
    column->addWidget(ports_box);
    const std::tuple<PortKind, QString, QString> kinds[] = {
        {PortKind::plain, tr("Port plain (en clair)"), "9001"},
        {PortKind::tls, tr("Port tls (TLS 1.3)"), "9002"},
        {PortKind::mtls, tr("Port mtls (TLS 1.3 avec certificat client)"), "9003"}};
    for (const auto& [kind, title, number] : kinds) {
        const auto base = "ports." + std::string(to_string(kind));
        auto* box = new QGroupBox(title);
        box->setCheckable(true);
        box->setChecked(false);
        auto* form = new QFormLayout(box);
        form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        add_line(form, base + ".listen", tr("Écoute (adresse IP:port)"), "0.0.0.0:" + number);
        add_line(form, base + ".upstream", tr("Serveur tlsrelay (hôte:port)"), "relais.exemple:" + number,
                 Field::Scope::client);
        add_line(form, base + ".server_name", tr("Nom attendu du serveur"), "relais.exemple",
                 kind == PortKind::plain ? Field::Scope::never : Field::Scope::client);
        connect(box, &QGroupBox::toggled, this, [this] {
            if (!loading_) emit changed();
        });
        ports_[kind] = box;
        sections_[base] = box;
        ports_layout->addWidget(box);
    }

    auto* dest = section("destination", tr("Destination (mode serveur)"));
    add_line(dest, "destination.address", tr("Adresse"), "10.0.0.5", Field::Scope::server);
    add_line(dest, "destination.port", tr("Port"), "8080", Field::Scope::server);
    add_line(dest, "destination.dial_timeout", tr("Délai de connexion"),
             QString::fromStdString(format_duration(destination.dial_timeout)), Field::Scope::server);
    add_line(dest, "destination.dial_retries", tr("Essais"), QString::number(destination.dial_retries),
             Field::Scope::server);
    add_line(dest, "destination.dial_backoff", tr("Attente entre essais"),
             QString::fromStdString(format_duration(destination.dial_backoff)), Field::Scope::server);

    auto* wl = section("whitelist", tr("Liste blanche (mode serveur)"));
    add_line(wl, "whitelist.file", tr("Fichier"), tr("/etc/tlsrelay/agence/whitelist.yaml"), Field::Scope::server);
    add_combo(wl, "whitelist.revoke_mode", tr("Pair retiré"), {"immediate", "next_renegotiation"}, true,
              Field::Scope::server);

    auto* source = section("source", tr("Connexions sortantes (mode client)"));
    add_line(source, "source_address", tr("Adresse source"), tr("(choisie par le système)"), Field::Scope::client);

    auto* cred = section("credentials", tr("PKI"));
    add_line(cred, "credentials.pki_root", tr("Répertoire PKI"), tr("/etc/tlsrelay/agence/pki"));
    add_combo(cred, "credentials.watch", tr("Surveillance (2 s)"), {"true", "false"});
    add_line(cred, "credentials.expiry_warning", tr("Alerte d'expiration"),
             QString::fromStdString(format_duration(credentials.expiry_warning)));

    auto* lim = section("limits", tr("Limites"));
    add_line(lim, "limits.idle_timeout", tr("Inactivité"), QString::fromStdString(format_duration(limits.idle_timeout)));
    add_line(lim, "limits.session_lifetime", tr("Durée de session"),
             QString::fromStdString(format_duration(limits.session_lifetime)));
    add_line(lim, "limits.session_jitter", tr("Variation de la durée"),
             QString::fromStdString(format_percent(limits.session_jitter)));
    add_line(lim, "limits.renegotiation_grace", tr("Délai de renégociation"),
             QString::fromStdString(format_duration(limits.renegotiation_grace)));
    add_line(lim, "limits.resume_buffer", tr("Tampon de reprise"), QString::fromStdString(format_size(limits.resume_buffer)));
    add_line(lim, "limits.handshake_timeout", tr("Délai de handshake"),
             QString::fromStdString(format_duration(limits.handshake_timeout)));
    add_line(lim, "limits.keepalive_interval", tr("Intervalle de PING"),
             QString::fromStdString(format_duration(limits.keepalive_interval)));
    add_line(lim, "limits.max_channels", tr("Canaux au plus"), QString::number(limits.max_channels));
    add_line(lim, "limits.shutdown_timeout", tr("Drain à l'arrêt"),
             QString::fromStdString(format_duration(limits.shutdown_timeout)));

    auto* log = section("logging", tr("Journalisation"));
    add_combo(log, "logging.level", tr("Niveau"), kLevels);
    add_combo(log, "logging.categories.activity", tr("Niveau « activity »"), kLevels);
    add_combo(log, "logging.categories.config", tr("Niveau « config »"), kLevels);
    add_combo(log, "logging.format", tr("Format"), {"text", "json"});
    add_line(log, "logging.output", tr("Sortie"), "stderr");

    auto* adm = section("admin", tr("Canal d'administration"));
    add_combo(adm, "admin.enabled", tr("Activé"), {"true", "false"});
    add_line(adm, "admin.endpoint", tr("Point d'accès"), tr("(par défaut, conseillé pour un service)"));

    column->addStretch();
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setWidget(content);
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(scroll);
    update_visibility();
}

QLineEdit* ConfigForm::add_line(QFormLayout* form, const std::string& path, const QString& label,
                                const QString& placeholder, Field::Scope scope) {
    auto* edit = new QLineEdit;
    edit->setObjectName(QString::fromStdString(path));
    edit->setPlaceholderText(placeholder);
    form->addRow(label, edit);
    fields_[path] = {edit, form, scope};
    connect(edit, &QLineEdit::textChanged, this, [this] {
        if (loading_) return;
        update_visibility();
        emit changed();
    });
    return edit;
}

QComboBox* ConfigForm::add_combo(QFormLayout* form, const std::string& path, const QString& label,
                                 const std::vector<QString>& values, bool with_default, Field::Scope scope) {
    auto* combo = new QComboBox;
    combo->setObjectName(QString::fromStdString(path));
    if (with_default) combo->addItem(tr("(par défaut)"), QString());
    for (const auto& v : values) combo->addItem(v, v);
    form->addRow(label, combo);
    fields_[path] = {combo, form, scope};
    connect(combo, &QComboBox::currentIndexChanged, this, [this] {
        if (loading_) return;
        update_visibility();
        emit changed();
    });
    return combo;
}

QString ConfigForm::value(const std::string& path) const {
    const auto it = fields_.find(path);
    if (it == fields_.end()) return {};
    if (auto* edit = qobject_cast<QLineEdit*>(it->second.widget)) return edit->text();
    return qobject_cast<QComboBox*>(it->second.widget)->currentData().toString();
}

void ConfigForm::set_value(const std::string& path, const QString& value) {
    const auto it = fields_.find(path);
    if (it == fields_.end()) return;
    if (auto* edit = qobject_cast<QLineEdit*>(it->second.widget)) {
        edit->setText(value);
        return;
    }
    auto* combo = qobject_cast<QComboBox*>(it->second.widget);
    int index = combo->findData(value);
    if (index < 0) {
        // Valeur hors liste (fichier invalide) : ajoutée pour être signalée par la validation.
        combo->addItem(value, value);
        index = combo->count() - 1;
    }
    combo->setCurrentIndex(index);
}

void ConfigForm::set_port_enabled(PortKind kind, bool enabled) { ports_.at(kind)->setChecked(enabled); }
bool ConfigForm::port_enabled(PortKind kind) const { return ports_.at(kind)->isChecked(); }

Mode ConfigForm::mode() const { return value("mode") == "server" ? Mode::server : Mode::client; }

std::vector<std::string> ConfigForm::load_yaml(const std::string& text) {
    std::vector<std::string> ignored;
    loading_ = true;
    for (auto& [path, field] : fields_) {
        if (auto* edit = qobject_cast<QLineEdit*>(field.widget)) {
            edit->clear();
        } else {
            auto* combo = qobject_cast<QComboBox*>(field.widget);
            combo->setCurrentIndex(0);
        }
    }
    for (auto& [kind, box] : ports_) box->setChecked(false);
    try {
        const YAML::Node root = YAML::Load(text);
        if (root.IsMap()) read_node(root, "", ignored);
        else if (root.IsDefined() && !root.IsNull()) ignored.emplace_back("(racine)");
    } catch (const YAML::Exception& e) {
        ignored.push_back("syntaxe YAML invalide : " + e.msg);
    }
    loading_ = false;
    update_visibility();
    emit changed();
    return ignored;
}

void ConfigForm::read_node(const YAML::Node& node, const std::string& path, std::vector<std::string>& ignored) {
    for (const auto& item : node) {
        const auto key = join(path, item.first.as<std::string>(""));
        const YAML::Node& value = item.second;
        if (fields_.count(key) && value.IsScalar()) {
            set_value(key, QString::fromStdString(value.Scalar()));
        } else if (std::find(kContainers.begin(), kContainers.end(), key) != kContainers.end() && value.IsMap()) {
            for (auto& [kind, box] : ports_) {
                if (key == "ports." + std::string(to_string(kind))) box->setChecked(true);
            }
            read_node(value, key, ignored);
        } else {
            ignored.push_back(key);
        }
    }
}

std::string ConfigForm::raw_yaml() const {
    YAML::Node root(YAML::NodeType::Map);
    for (const auto& [kind, box] : ports_) {
        if (box->isChecked()) put(root, split_path("ports." + std::string(to_string(kind))), 0, YAML::Node(YAML::NodeType::Map));
    }
    for (const auto& [path, field] : fields_) {
        const auto text = value(path);
        if (text.isEmpty()) continue;
        if (path.rfind("ports.", 0) == 0) {
            const auto kind = path.substr(6, path.find('.', 6) - 6);
            bool enabled = false;
            for (const auto& [k, box] : ports_) enabled |= to_string(k) == kind && box->isChecked();
            if (!enabled) continue;
        }
        put(root, split_path(path), 0, YAML::Node(text.toStdString()));
    }
    YAML::Emitter out;
    out << root;
    return out.c_str();
}

LoadResult ConfigForm::validate() {
    auto result = load_config_string(raw_yaml());
    clear_marks();
    for (const auto& issue : result.errors) {
        if (auto* w = widget_for(issue.path)) mark(w, QString::fromStdString(issue.message));
    }
    return result;
}

QWidget* ConfigForm::widget_for(const std::string& path) const {
    for (std::string p = path;;) {
        if (const auto it = fields_.find(p); it != fields_.end()) return it->second.widget;
        if (const auto it = sections_.find(p); it != sections_.end()) return it->second;
        const auto dot = p.rfind('.');
        if (dot == std::string::npos) return nullptr;
        p.resize(dot);
    }
}

bool ConfigForm::is_shown(const std::string& path) const {
    const auto it = fields_.find(path);
    return it != fields_.end() && it->second.form->isRowVisible(it->second.widget);
}

void ConfigForm::clear_marks() {
    for (auto* w : marked_) {
        w->setProperty("invalid", false);
        w->setToolTip({});
        w->style()->unpolish(w);
        w->style()->polish(w);
    }
    marked_.clear();
}

void ConfigForm::mark(QWidget* widget, const QString& message) {
    const auto previous = widget->property("invalid").toBool() ? widget->toolTip() + "\n" : QString();
    widget->setProperty("invalid", true);
    widget->setToolTip(previous + message);
    widget->style()->unpolish(widget);
    widget->style()->polish(widget);
    marked_.push_back(widget);
}

void ConfigForm::update_visibility() {
    const bool server = mode() == Mode::server;
    std::map<QGroupBox*, bool> any_visible;
    for (const auto& [path, field] : fields_) {
        bool relevant = true;
        switch (field.scope) {
            case Field::Scope::both: relevant = true; break;
            case Field::Scope::client: relevant = !server; break;
            case Field::Scope::server: relevant = server; break;
            case Field::Scope::never: relevant = false; break;
        }
        // Un champ sans objet reste visible s'il a une valeur : l'erreur
        // signalée par la validation doit pouvoir être corrigée.
        const bool shown = relevant || !value(path).isEmpty();
        field.form->setRowVisible(field.widget, shown);
    }
    for (const auto& name : {"destination", "whitelist", "source"}) {
        auto* box = sections_.at(name);
        bool shown = false;
        for (const auto& [path, field] : fields_) {
            if (field.form->parentWidget() == box) shown |= field.form->isRowVisible(field.widget);
        }
        box->setVisible(shown);
    }
}

}  // namespace tlsrelay::admin
