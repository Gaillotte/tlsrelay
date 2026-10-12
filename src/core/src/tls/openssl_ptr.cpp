#include "tlsrelay/tls/openssl_ptr.hpp"

#include <openssl/asn1.h>
#include <openssl/err.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <vector>

namespace tlsrelay::tls {

std::string take_openssl_errors() {
    std::string out;
    while (const unsigned long code = ERR_get_error()) {
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof buffer);
        if (!out.empty()) out += "; ";
        out += buffer;
    }
    return out.empty() ? "erreur OpenSSL inconnue" : out;
}

std::string name_to_string(const X509_NAME* name) {
    if (!name) return "?";
    BioPtr bio(BIO_new(BIO_s_mem()));
    // RFC 2253, mais caractères non ASCII affichés en UTF-8 plutôt qu'échappés.
    X509_NAME_print_ex(bio.get(), name, 0, (XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB) | ASN1_STRFLGS_UTF8_CONVERT);
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : std::string();
}

std::string subject_of(const X509* cert) {
    return cert ? name_to_string(X509_get_subject_name(cert)) : "?";
}

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(' ');
    if (first == std::string::npos) return {};
    return s.substr(first, s.find_last_not_of(' ') - first + 1);
}

}  // namespace

X509NamePtr parse_dn(std::string_view text, std::string& error) {
    // Découpage en composants « type=valeur » séparés par des virgules non échappées.
    std::vector<std::pair<std::string, std::string>> parts;
    std::string type, value;
    bool in_value = false;
    std::size_t value_end = 0;  // fin de la partie de valeur à conserver (espaces échappés inclus)
    auto flush = [&]() -> bool {
        type = trim(type);
        value.resize(std::max(value_end, value.find_last_not_of(' ') == std::string::npos ? 0 : value.find_last_not_of(' ') + 1));
        if (type.empty() || !in_value) {
            error = "composant sans « type=valeur »";
            return false;
        }
        parts.emplace_back(type, value);
        type.clear();
        value.clear();
        value_end = 0;
        in_value = false;
        return true;
    };
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (!in_value) {
            if (c == '=') in_value = true;
            else if (c == ',' || c == '+') {
                error = "composant sans « type=valeur »";
                return nullptr;
            } else type += c;
            continue;
        }
        if (c == '\\') {
            if (i + 1 >= text.size()) {
                error = "échappement incomplet en fin de nom";
                return nullptr;
            }
            const char n = text[i + 1];
            if (i + 2 < text.size() && hex_value(n) >= 0 && hex_value(text[i + 2]) >= 0) {
                value += static_cast<char>(hex_value(n) * 16 + hex_value(text[i + 2]));
                i += 2;
            } else {
                value += n;
                i += 1;
            }
            value_end = value.size();
            continue;
        }
        if (c == ',') {
            if (!flush()) return nullptr;
            continue;
        }
        if (c == '+') {
            error = "les noms à plusieurs valeurs (« + ») ne sont pas acceptés";
            return nullptr;
        }
        if (c == '#' && value.empty()) {
            error = "les valeurs hexadécimales (« # ») ne sont pas acceptées";
            return nullptr;
        }
        if (c == ' ' && value.empty()) continue;  // espaces après « = »
        value += c;
    }
    if (!flush()) return nullptr;

    // RFC 4514 : le plus spécifique en premier ; X509_NAME : le plus général en premier.
    X509NamePtr name(X509_NAME_new());
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        // Types insensibles à la casse (RFC 4514) : « cn » est accepté comme « CN ».
        std::string upper = it->first;
        std::transform(upper.begin(), upper.end(), upper.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        const auto* bytes = reinterpret_cast<const unsigned char*>(it->second.c_str());
        const int length = static_cast<int>(it->second.size());
        if (X509_NAME_add_entry_by_txt(name.get(), it->first.c_str(), MBSTRING_UTF8, bytes, length, -1, 0) != 1 &&
            (ERR_clear_error(),
             X509_NAME_add_entry_by_txt(name.get(), upper.c_str(), MBSTRING_UTF8, bytes, length, -1, 0) != 1)) {
            ERR_clear_error();
            error = "attribut inconnu ou valeur invalide : " + it->first + "=" + it->second;
            return nullptr;
        }
    }
    return name;
}

std::string not_after_of(const X509* cert) { return cert ? time_to_string(X509_get0_notAfter(cert)) : "?"; }

std::string time_to_string(const ASN1_TIME* time) {
    std::tm tm{};
    if (!time || ASN1_TIME_to_tm(time, &tm) != 1) return "?";
    char buffer[32];
    (void)std::strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%SZ", &tm);
    return buffer;
}

}  // namespace tlsrelay::tls
