#pragma once

// Outils internes du module PKI : fichiers, encodage PEM, aléa.

#include "tlsrelay/tls/openssl_ptr.hpp"

#include <openssl/pem.h>
#include <openssl/rand.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace tlsrelay::pki::detail {

[[noreturn]] inline void fail(const std::string& message) {
    const auto details = tls::take_openssl_errors();
    throw std::runtime_error(details.empty() ? message : message + " (" + details + ")");
}

inline std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("lecture impossible : " + path.string());
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

// Écrit un fichier ; secret : lisible par le seul propriétaire (Linux).
inline void write_file(const std::filesystem::path& path, const std::string& content, bool secret = false) {
#ifdef _WIN32
    (void)secret;  // droits gérés par ACL (voir pki/authority.cpp)
#else
    // Créé directement avec les bons droits : aucun instant où la clé serait lisible.
    const auto old = ::umask(secret ? 0077 : 0022);
#endif
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    out.close();
#ifndef _WIN32
    ::umask(old);
    if (secret) ::chmod(path.c_str(), 0600);
#endif
    if (!out) throw std::runtime_error("écriture impossible : " + path.string());
}

// Crée un répertoire réservé au propriétaire (Linux).
inline void make_private_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) throw std::runtime_error("création impossible : " + dir.string() + " : " + ec.message());
#ifndef _WIN32
    ::chmod(dir.c_str(), 0700);
#endif
}

inline std::string bio_text(BIO* bio) {
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<std::size_t>(size));
}

inline std::string pem_of(const X509* cert) {
    tls::BioPtr bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_X509(bio.get(), const_cast<X509*>(cert))) fail("encodage PEM impossible");
    return bio_text(bio.get());
}

inline tls::X509Ptr cert_from_pem(const std::string& pem, const std::string& what) {
    tls::BioPtr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    tls::X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) fail(what + " : certificat illisible");
    return cert;
}

// Clé ECDSA sur la courbe donnée (« P-256 », « P-384 »).
inline tls::EvpPkeyPtr generate_ec_key(const char* curve) {
    tls::EvpPkeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", curve));
    if (!key) fail(std::string("génération de clé ") + curve + " impossible");
    return key;
}

// Numéro de série aléatoire de 128 bits, positif et non nul (RFC 5280 §4.1.2.2).
inline std::string random_serial_hex() {
    unsigned char bytes[16];
    do {
        if (RAND_bytes(bytes, sizeof bytes) != 1) fail("générateur aléatoire indisponible");
        bytes[0] &= 0x7f;
    } while (bytes[0] == 0);
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string hex;
    for (const auto b : bytes) {
        hex += digits[b >> 4];
        hex += digits[b & 0xf];
    }
    return hex;
}

}  // namespace tlsrelay::pki::detail
