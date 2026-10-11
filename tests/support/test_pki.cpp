#include "test_pki.hpp"

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <fstream>
#include <random>
#include <stdexcept>

namespace testpki {
namespace {

using tlsrelay::tls::BioPtr;

void check(bool ok, const char* what) {
    if (!ok) throw std::runtime_error(std::string("PKI de test : ") + what + " : " + tlsrelay::tls::take_openssl_errors());
}

void add_extension(X509* cert, X509V3_CTX* ctx, int nid, const std::string& value) {
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, ctx, nid, value.c_str());
    check(ext != nullptr, "extension");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

std::string read_bio(BIO* bio) {
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<std::size_t>(size));
}

}  // namespace

Issued make_certificate(const CertOptions& options, const Issued* issuer) {
    Issued out;
    out.key.reset(EVP_EC_gen(options.curve));
    check(out.key != nullptr, "génération de clé");

    out.cert.reset(X509_new());
    X509* cert = out.cert.get();
    X509_set_version(cert, 2);
    std::uint64_t serial = 0;
    RAND_bytes(reinterpret_cast<unsigned char*>(&serial), sizeof serial);
    ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert), serial >> 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), options.not_before_offset);
    X509_gmtime_adj(X509_getm_notAfter(cert), options.not_after_offset);
    X509_set_pubkey(cert, out.key.get());

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>("tlsrelay-test"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                               reinterpret_cast<const unsigned char*>(options.common_name.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, issuer ? X509_get_subject_name(issuer->cert.get()) : name);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer ? issuer->cert.get() : cert, cert, nullptr, nullptr, 0);
    if (options.ca) {
        add_extension(cert, &ctx, NID_basic_constraints, issuer ? "critical,CA:TRUE,pathlen:0" : "critical,CA:TRUE");
        add_extension(cert, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add_extension(cert, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        add_extension(cert, &ctx, NID_key_usage, "critical,digitalSignature");
    }
    if (options.usage == Usage::server) add_extension(cert, &ctx, NID_ext_key_usage, "serverAuth");
    if (options.usage == Usage::client) add_extension(cert, &ctx, NID_ext_key_usage, "clientAuth");
    add_extension(cert, &ctx, NID_subject_key_identifier, "hash");
    add_extension(cert, &ctx, NID_authority_key_identifier, "keyid:always");
    std::string san;
    for (const auto& d : options.dns) san += (san.empty() ? "" : ",") + std::string("DNS:") + d;
    for (const auto& ip : options.ips) san += (san.empty() ? "" : ",") + std::string("IP:") + ip;
    if (!san.empty()) add_extension(cert, &ctx, NID_subject_alt_name, san);

    const EVP_PKEY* signer = issuer ? issuer->key.get() : out.key.get();
    check(X509_sign(cert, const_cast<EVP_PKEY*>(signer), EVP_sha384()) > 0, "signature");
    return out;
}

std::string pem(const X509* cert) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(bio.get(), const_cast<X509*>(cert));
    return read_bio(bio.get());
}

std::string pem(const EVP_PKEY* key) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(bio.get(), const_cast<EVP_PKEY*>(key), nullptr, nullptr, 0, nullptr, nullptr);
    return read_bio(bio.get());
}

std::string encrypted_pem(const EVP_PKEY* key, const char* password) {
    BioPtr bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PKCS8PrivateKey(bio.get(), const_cast<EVP_PKEY*>(key), EVP_aes_256_cbc(), password,
                                  static_cast<int>(std::char_traits<char>::length(password)), nullptr, nullptr);
    return read_bio(bio.get());
}

Hierarchy Hierarchy::create(const std::string& label) {
    Hierarchy h;
    h.root = make_certificate({.common_name = label + " Racine", .ca = true, .curve = "P-384"});
    h.servers_ca = make_certificate({.common_name = label + " AC Serveurs", .ca = true, .usage = Usage::server,
                                     .curve = "P-384"}, &h.root);
    h.clients_ca = make_certificate({.common_name = label + " AC Clients", .ca = true, .usage = Usage::client,
                                     .curve = "P-384"}, &h.root);
    h.server = make_certificate({.common_name = "relay.test", .usage = Usage::server, .dns = {"relay.test"},
                                 .ips = {"127.0.0.1"}}, &h.servers_ca);
    h.client = make_certificate({.common_name = "client.test", .usage = Usage::client}, &h.clients_ca);
    return h;
}

void write_generation(const std::filesystem::path& pki_root, const std::string& name, const GenerationFiles& files,
                      bool activate) {
    const auto dir = pki_root / name;
    std::filesystem::create_directories(dir);
    auto write = [&](const char* file, const std::optional<std::string>& content) {
        if (content) std::ofstream(dir / file, std::ios::binary) << *content;
    };
    write("key.pem", files.key);
    write("cert.pem", files.cert);
    write("chain.pem", files.chain);
    write("trust-roots.pem", files.trust_roots);
    write("trust-issuer.pem", files.trust_issuer);
    if (!activate) return;
    // Fichier temporaire puis renommage : un service qui surveille current ne lit jamais un fichier partiel.
    std::ofstream(pki_root / "current.tmp", std::ios::binary) << name << "\n";
    std::filesystem::rename(pki_root / "current.tmp", pki_root / "current");
}

GenerationFiles server_files(const Hierarchy& h) {
    return {pem(h.server.key.get()), pem(h.server.cert.get()), pem(h.servers_ca.cert.get()), pem(h.root.cert.get()),
            pem(h.clients_ca.cert.get())};
}

GenerationFiles client_files(const Hierarchy& h) {
    return {pem(h.client.key.get()), pem(h.client.cert.get()), pem(h.clients_ca.cert.get()), pem(h.root.cert.get()),
            pem(h.servers_ca.cert.get())};
}

TempDir::TempDir() {
    static std::atomic<int> counter{0};
    std::random_device rd;
    path_ = std::filesystem::temp_directory_path() /
            ("tlsrelay-test-" + std::to_string(rd()) + "-" + std::to_string(counter++));
    std::filesystem::create_directories(path_);
}

TempDir::~TempDir() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
}

}  // namespace testpki
