#pragma once

#include <string>
#include <string_view>
#include <vector>

// Line-by-line differences between two texts (preview before saving
// in the tlsrelay-admin editor).
namespace tlsrelay {

struct DiffLine {
    enum class Kind { same, removed, added };
    Kind kind = Kind::same;
    std::string text;  // without line ending
};

// Longest common subsequence: removed lines precede the added
// lines that replace them. Line endings \r\n and \n are equivalent.
std::vector<DiffLine> diff_lines(std::string_view before, std::string_view after);

// True if both texts have the same lines.
bool same_lines(const std::vector<DiffLine>& diff);

// Text form: "-" removed line, "+" added line, "␣" unchanged;
// context: number of unchanged lines kept around the changes.
std::string format_diff(const std::vector<DiffLine>& diff, std::size_t context = 3);

}  // namespace tlsrelay
