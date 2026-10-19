#include "whitelist_editor.hpp"

#include <yaml-cpp/yaml.h>

#include <QBrush>
#include <QColor>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <regex>

namespace tlsrelay::admin {
namespace {

constexpr PortKind kPortOfColumn[] = {PortKind::plain, PortKind::tls, PortKind::mtls};

std::optional<PortKind> port_kind(const std::string& text) {
    for (auto kind : kPortOfColumn) {
        if (text == to_string(kind)) return kind;
    }
    return std::nullopt;
}

}  // namespace

WhitelistEditor::WhitelistEditor(QWidget* parent) : QWidget(parent), table_(new QTableWidget(0, column_count)) {
    table_->setHorizontalHeaderLabels(
        {tr("Name"), tr("IP address or range"), "plain", "tls", "mtls", tr("Certificate subject (DN)")});
    table_->horizontalHeader()->setSectionResizeMode(subject, QHeaderView::Stretch);
    table_->setColumnWidth(name, 160);
    table_->setColumnWidth(ip, 190);
    for (int c : {plain, tls, mtls}) table_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    connect(table_, &QTableWidget::itemChanged, this, [this] {
        if (!loading_) emit changed();
    });

    auto* add = new QPushButton(tr("Add"));
    auto* remove = new QPushButton(tr("Remove"));
    auto* up = new QPushButton(tr("Move up"));
    auto* down = new QPushButton(tr("Move down"));
    connect(add, &QPushButton::clicked, this, &WhitelistEditor::add_peer);
    connect(remove, &QPushButton::clicked, this, &WhitelistEditor::remove_selected);
    connect(up, &QPushButton::clicked, this, [this] { move_selected(-1); });
    connect(down, &QPushButton::clicked, this, [this] { move_selected(1); });
    auto* buttons = new QHBoxLayout;
    for (auto* b : {add, remove, up, down}) buttons->addWidget(b);
    buttons->addStretch();

    auto* help = new QLabel(tr("No port box checked: default ports (plain and tls, plus mtls if a subject is "
                               "given). The mtls port requires a subject; address and subject must be in the same "
                               "entry."));
    help->setWordWrap(true);
    auto* layout = new QVBoxLayout(this);
    layout->addWidget(table_);
    layout->addLayout(buttons);
    layout->addWidget(help);
}

void WhitelistEditor::set_row(int row, const whitelist::PeerSpec& peer) {
    table_->setItem(row, name, new QTableWidgetItem(QString::fromStdString(peer.name)));
    table_->setItem(row, ip, new QTableWidgetItem(QString::fromStdString(peer.ip)));
    for (int c = plain; c <= mtls; ++c) {
        auto* item = new QTableWidgetItem;
        item->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        const bool on = peer.ports && peer.ports->count(kPortOfColumn[c - plain]);
        item->setCheckState(on ? Qt::Checked : Qt::Unchecked);
        table_->setItem(row, c, item);
    }
    table_->setItem(row, subject, new QTableWidgetItem(QString::fromStdString(peer.subject)));
}

void WhitelistEditor::set_peers(const std::vector<whitelist::PeerSpec>& peers) {
    loading_ = true;
    table_->setRowCount(0);
    table_->setRowCount(static_cast<int>(peers.size()));
    for (std::size_t i = 0; i < peers.size(); ++i) set_row(static_cast<int>(i), peers[i]);
    loading_ = false;
    emit changed();
}

std::vector<std::string> WhitelistEditor::load_yaml(const std::string& text) {
    std::vector<std::string> ignored;
    std::vector<whitelist::PeerSpec> peers;
    try {
        const YAML::Node root = YAML::Load(text);
        const YAML::Node list = root.IsMap() ? root["peers"] : YAML::Node();
        if (!list.IsSequence()) ignored.emplace_back("peers");
        for (std::size_t i = 0; list.IsSequence() && i < list.size(); ++i) {
            const YAML::Node entry = list[i];
            const auto path = "peers[" + std::to_string(i) + "]";
            whitelist::PeerSpec peer;
            if (!entry.IsMap()) {
                ignored.push_back(path);
                continue;
            }
            for (const auto& item : entry) {
                const auto key = item.first.as<std::string>("");
                const YAML::Node& v = item.second;
                if (key == "name" && v.IsScalar()) peer.name = v.Scalar();
                else if (key == "ip" && v.IsScalar()) peer.ip = v.Scalar();
                else if (key == "subject" && v.IsScalar()) peer.subject = v.Scalar();
                else if (key == "ports" && v.IsSequence()) {
                    peer.ports.emplace();
                    for (const auto& p : v) {
                        auto kind = p.IsScalar() ? port_kind(p.Scalar()) : std::nullopt;
                        if (kind) peer.ports->insert(*kind);
                        else ignored.push_back(path + ".ports: " + (p.IsScalar() ? p.Scalar() : "?"));
                    }
                    if (peer.ports->empty()) {
                        ignored.push_back(path + ".ports: empty list (default ports)");
                        peer.ports.reset();
                    }
                } else {
                    ignored.push_back(path);
                    ignored.back().append(".").append(key);
                }
            }
            peers.push_back(std::move(peer));
        }
    } catch (const YAML::Exception& e) {
        ignored.push_back("invalid YAML syntax: " + e.msg);
    }
    set_peers(peers);
    return ignored;
}

std::vector<whitelist::PeerSpec> WhitelistEditor::peers() const {
    std::vector<whitelist::PeerSpec> out;
    auto text = [&](int row, int column) {
        const auto* item = table_->item(row, column);
        return item ? item->text().trimmed().toStdString() : std::string();
    };
    for (int row = 0; row < table_->rowCount(); ++row) {
        whitelist::PeerSpec peer{text(row, name), text(row, ip), std::nullopt, text(row, subject)};
        std::set<PortKind> ports;
        for (int c = plain; c <= mtls; ++c) {
            const auto* item = table_->item(row, c);
            if (item && item->checkState() == Qt::Checked) ports.insert(kPortOfColumn[c - plain]);
        }
        if (!ports.empty()) peer.ports = ports;
        out.push_back(std::move(peer));
    }
    return out;
}

std::string WhitelistEditor::yaml() const { return whitelist::to_yaml(peers()); }

whitelist::LoadResult WhitelistEditor::validate() {
    auto result = whitelist::Whitelist::load_string(yaml());
    clear_marks();
    static const std::regex entry(R"(peers\[(\d+)\](?:\.(\w+))?)");
    for (const auto& issue : result.errors) {
        std::smatch m;
        const auto message = QString::fromStdString(issue.message);
        if (!std::regex_match(issue.path, m, entry)) continue;  // "peers": shown in the issue list
        const int row = std::stoi(m[1]);
        const std::string key = m[2];
        if (key == "name") mark(row, name, message);
        else if (key == "ip") mark(row, ip, message);
        else if (key == "subject") mark(row, subject, message);
        else if (key == "ports") {
            for (int c = plain; c <= mtls; ++c) mark(row, c, message);
        } else {
            for (int c = 0; c < column_count; ++c) mark(row, c, message);
        }
    }
    return result;
}

void WhitelistEditor::clear_marks() {
    loading_ = true;
    for (int row = 0; row < table_->rowCount(); ++row) {
        for (int c = 0; c < column_count; ++c) {
            if (auto* item = table_->item(row, c)) {
                item->setBackground(QBrush());
                item->setToolTip({});
                item->setData(Qt::UserRole, false);
            }
        }
    }
    loading_ = false;
}

void WhitelistEditor::mark(int row, int column, const QString& message) {
    auto* item = table_->item(row, column);
    if (!item) return;
    loading_ = true;
    item->setBackground(QColor(255, 205, 210));
    item->setToolTip(item->toolTip().isEmpty() ? message : item->toolTip() + "\n" + message);
    item->setData(Qt::UserRole, true);  // in error (tests)
    loading_ = false;
}

void WhitelistEditor::add_peer() {
    loading_ = true;
    const int row = table_->rowCount();
    table_->insertRow(row);
    set_row(row, {});
    loading_ = false;
    table_->setCurrentCell(row, name);
    emit changed();
}

void WhitelistEditor::remove_selected() {
    const int row = table_->currentRow();
    if (row < 0) return;
    table_->removeRow(row);
    emit changed();
}

void WhitelistEditor::move_selected(int delta) {
    const int row = table_->currentRow();
    const int target = row + delta;
    if (row < 0 || target < 0 || target >= table_->rowCount()) return;
    auto all = peers();
    std::swap(all[static_cast<std::size_t>(row)], all[static_cast<std::size_t>(target)]);
    set_peers(all);
    table_->setCurrentCell(target, name);
}

}  // namespace tlsrelay::admin
