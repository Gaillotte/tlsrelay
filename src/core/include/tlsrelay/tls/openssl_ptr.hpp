#pragma once

// Smart pointers for OpenSSL objects: no manual freeing in the rest of
// the code (PLAN §6, C++ memory risks).

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <memory>
#include <string>
#include <string_view>

namespace tlsrelay::tls {

struct BioDeleter { void operator()(BIO* p) const { BIO_free_all(p); } };
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct SslCtxDeleter { void operator()(SSL_CTX* p) const { SSL_CTX_free(p); } };
struct SslDeleter { void operator()(SSL* p) const { SSL_free(p); } };
struct X509Deleter { void operator()(X509* p) const { X509_free(p); } };
struct X509NameDeleter { void operator()(X509_NAME* p) const { X509_NAME_free(p); } };
struct X509StoreDeleter { void operator()(X509_STORE* p) const { X509_STORE_free(p); } };
struct X509StoreCtxDeleter { void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); } };

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using X509NamePtr = std::unique_ptr<X509_NAME, X509NameDeleter>;
using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

// Empties the thread's OpenSSL error queue and returns the messages, separated by "; ".
std::string take_openssl_errors();

// Subject of a certificate in RFC 2253 format (e.g. "CN=relay.example,O=MyCompany").
std::string subject_of(const X509* cert);

// Distinguished name in RFC 4514 format, most specific element first
// (e.g. "CN=relay-lyon.example,O=MyCompany"). Multi-valued names
// ("+") and hexadecimal values ("#") are not accepted.
// Returns nullptr and fills error on error.
X509NamePtr parse_dn(std::string_view text, std::string& error);

std::string name_to_string(const X509_NAME* name);

// Expiry date, in UTC (e.g. "2027-10-11 12:00:00Z").
std::string not_after_of(const X509* cert);

// Date in UTC, same format; "?" if unreadable.
std::string time_to_string(const ASN1_TIME* time);

}  // namespace tlsrelay::tls
