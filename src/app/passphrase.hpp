#pragma once

#include <optional>
#include <string>

namespace tlsrelay::app {

// Phrase de passe de l'AC : fichier (première ligne), sinon variable
// TLSRELAY_CA_PASSPHRASE, sinon saisie au clavier sans écho (confirm : saisie
// répétée). std::nullopt si la saisie échoue ou ne concorde pas (message affiché).
std::optional<std::string> read_passphrase(const std::string& file, bool confirm);

}  // namespace tlsrelay::app
