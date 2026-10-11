#pragma once

// Pointeurs intelligents pour les objets OpenSSL : aucune libération manuelle
// dans le reste du code (PLAN §6, risques mémoire du C++).

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <memory>
#include <string>

namespace tlsrelay::tls {

struct BioDeleter { void operator()(BIO* p) const { BIO_free_all(p); } };
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct SslCtxDeleter { void operator()(SSL_CTX* p) const { SSL_CTX_free(p); } };
struct SslDeleter { void operator()(SSL* p) const { SSL_free(p); } };
struct X509Deleter { void operator()(X509* p) const { X509_free(p); } };
struct X509StoreDeleter { void operator()(X509_STORE* p) const { X509_STORE_free(p); } };
struct X509StoreCtxDeleter { void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); } };

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

// Vide la file d'erreurs OpenSSL du thread et retourne les messages, séparés par « ; ».
std::string take_openssl_errors();

// Sujet d'un certificat au format RFC 2253 (ex. "CN=relay.example,O=MonEntreprise").
std::string subject_of(const X509* cert);

// Date de fin de validité, en UTC (ex. "2027-10-11 12:00:00Z").
std::string not_after_of(const X509* cert);

}  // namespace tlsrelay::tls
