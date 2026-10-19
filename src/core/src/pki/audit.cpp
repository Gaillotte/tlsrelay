#include "tlsrelay/pki/audit.hpp"

#include "files.hpp"

#include <openssl/evp.h>

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <stdexcept>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

namespace tlsrelay::pki {
namespace {

namespace fs = std::filesystem;

constexpr const char* kAuditFile = "audit.log";
const std::string kZeroHash(64, '0');

std::string clean(std::string text) {
    for (auto& c : text) {
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    }
    return text;
}

std::string sha256_hex(const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), digest, &size, EVP_sha256(), nullptr) != 1) {
        detail::fail("cannot compute SHA-256 digest");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    for (unsigned i = 0; i < size; ++i) {
        hex += digits[digest[i] >> 4];
        hex += digits[digest[i] & 0xf];
    }
    return hex;
}

// Hash of a line, chained to the previous one.
std::string link_hash(const std::string& previous, const std::string& body) {
    std::string data = previous;
    data += '\t';
    data += body;
    return sha256_hex(data);
}

std::string now_utc() {
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[32];
    (void)std::strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
        const auto tab = line.find('\t', start);
        fields.push_back(line.substr(start, tab - start));
        if (tab == std::string::npos) break;
        start = tab + 1;
    }
    return fields;
}

}  // namespace

std::string current_operator() {
#ifdef _WIN32
    wchar_t name[256];
    DWORD size = 256;
    if (GetUserNameW(name, &size) && size > 1) {
        const int length = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
        std::string out(static_cast<std::size_t>(length > 0 ? length : 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, name, -1, out.data(), length, nullptr, nullptr);
        out.resize(std::strlen(out.c_str()));
        if (!out.empty()) return out;
    }
#else
    if (const passwd* pw = ::getpwuid(::geteuid()); pw && pw->pw_name) return pw->pw_name;
    if (const char* user = std::getenv("USER"); user && *user) return user;
#endif
    return "unknown";
}

AuditLog read_audit(const fs::path& ca_dir) {
    // A directory that is not a CA (typo) must not pass for an intact log.
    std::error_code ec;
    if (!fs::is_regular_file(ca_dir / "root.cert.pem", ec)) {
        throw std::runtime_error(ca_dir.string() + " is not a tlsrelay CA directory (root.cert.pem missing)");
    }
    AuditLog log;
    std::ifstream in(ca_dir / kAuditFile, std::ios::binary);
    if (!in) return log;
    std::string previous = kZeroHash;
    std::size_t number = 0;
    for (std::string line; std::getline(in, line);) {
        ++number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto fields = split_tabs(line);
        if (fields.size() != 5) {
            log.broken_line = number;
            log.problem = "malformed line";
            return log;
        }
        const auto body = line.substr(0, line.rfind('\t'));
        if (link_hash(previous, body) != fields[4]) {
            log.broken_line = number;
            log.problem = "wrong hash: line modified, deleted or inserted";
            return log;
        }
        previous = fields[4];
        log.entries.push_back({fields[0], fields[1], fields[2], fields[3]});
    }
    return log;
}

void append_audit(const fs::path& ca_dir, const std::string& operation, const std::string& details) {
    // Last hash: that of the last line, even if the chain is broken
    // further up (verification reports it; appending remains possible).
    std::string previous = kZeroHash;
    {
        std::ifstream in(ca_dir / kAuditFile, std::ios::binary);
        for (std::string line; std::getline(in, line);) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            const auto tab = line.rfind('\t');
            if (tab != std::string::npos) previous = line.substr(tab + 1);
        }
    }
    const auto body = clean(now_utc()) + "\t" + clean(current_operator()) + "\t" + clean(operation) + "\t" + clean(details);
    const auto line = body + "\t" + link_hash(previous, body) + "\n";
    std::ofstream out(ca_dir / kAuditFile, std::ios::binary | std::ios::app);
    out << line;
    out.close();
    if (!out) throw std::runtime_error("cannot write audit log: " + (ca_dir / kAuditFile).string());
}

}  // namespace tlsrelay::pki
