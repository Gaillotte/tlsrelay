#pragma once

#include <string>
#include <string_view>
#include <vector>

// Différences ligne à ligne entre deux textes (aperçu avant enregistrement
// dans l'éditeur tlsrelay-admin).
namespace tlsrelay {

struct DiffLine {
    enum class Kind { same, removed, added };
    Kind kind = Kind::same;
    std::string text;  // sans fin de ligne
};

// Plus longue sous-suite commune : les lignes retirées précèdent les lignes
// ajoutées qui les remplacent. Les fins de ligne \r\n et \n sont équivalentes.
std::vector<DiffLine> diff_lines(std::string_view before, std::string_view after);

// Vrai si les deux textes ont les mêmes lignes.
bool same_lines(const std::vector<DiffLine>& diff);

// Forme texte : « - » ligne retirée, « + » ligne ajoutée, « ␣ » inchangée ;
// context : nombre de lignes inchangées gardées autour des modifications.
std::string format_diff(const std::vector<DiffLine>& diff, std::size_t context = 3);

}  // namespace tlsrelay
