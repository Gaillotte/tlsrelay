#include "tlsrelay/tls/openssl_ptr.hpp"

#include <openssl/asn1.h>
#include <openssl/err.h>

#include <ctime>

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

std::string subject_of(const X509* cert) {
    if (!cert) return "?";
    BioPtr bio(BIO_new(BIO_s_mem()));
    X509_NAME_print_ex(bio.get(), X509_get_subject_name(cert), 0, XN_FLAG_RFC2253);
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : std::string();
}

std::string not_after_of(const X509* cert) {
    if (!cert) return "?";
    std::tm tm{};
    if (ASN1_TIME_to_tm(X509_get0_notAfter(cert), &tm) != 1) return "?";
    char buffer[32];
    std::strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%SZ", &tm);
    return buffer;
}

}  // namespace tlsrelay::tls
