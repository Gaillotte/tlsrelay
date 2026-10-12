#include "document.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace tlsrelay::admin {

namespace fs = std::filesystem;

std::optional<std::string> read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

void write_with_backup(const fs::path& path, const std::string& content) {
    const auto previous = read_text(path);
    if (previous && *previous == content) return;
    std::error_code ec;
    if (path.has_parent_path()) fs::create_directories(path.parent_path(), ec);
    if (previous) {
        auto backup = path;
        backup += ".bak";
        fs::copy_file(path, backup, fs::copy_options::overwrite_existing, ec);
        if (ec) throw std::runtime_error("copie de sauvegarde impossible : " + backup.string() + " : " + ec.message());
    }
    auto tmp = path;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out << content;
        out.close();
        if (!out) throw std::runtime_error("écriture impossible : " + tmp.string());
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        throw std::runtime_error("remplacement impossible : " + path.string());
    }
}

fs::path resolve_from(const fs::path& config_path, const std::string& file) {
    auto target = to_path(QString::fromStdString(file));
    if (target.empty() || target.is_absolute()) return target;
    return config_path.parent_path() / target;
}

fs::path to_path(const QString& text) {
    const QByteArray utf8 = text.toUtf8();
    std::u8string bytes(utf8.size(), u8'\0');
    for (qsizetype i = 0; i < utf8.size(); ++i) bytes[static_cast<std::size_t>(i)] = static_cast<char8_t>(utf8[i]);
    return fs::path(bytes);
}

QString to_qstring(const fs::path& path) {
    const auto bytes = path.u8string();
    return QString::fromUtf8(reinterpret_cast<const char*>(bytes.data()), static_cast<qsizetype>(bytes.size()));
}

}  // namespace tlsrelay::admin
