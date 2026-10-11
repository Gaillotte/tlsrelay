#pragma once

#include <string>
#include <vector>

namespace testkit {

struct PkiOptions {
    std::string out;
    std::string server_subject = "CN=relay.test,O=tlsrelay-test";
    std::vector<std::string> server_sans = {"relay.test", "127.0.0.1", "::1"};
    std::string client_subject = "CN=client.test,O=tlsrelay-test";
};

// Crée la PKI de test (ou, si elle existe, une nouvelle génération activée).
int run_pki(const PkiOptions& options);

}  // namespace testkit
