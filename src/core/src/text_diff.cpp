#include "tlsrelay/text_diff.hpp"

#include <algorithm>
#include <cstdint>

namespace tlsrelay {
namespace {

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    while (!text.empty()) {
        const auto end = text.find('\n');
        auto line = text.substr(0, end);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        lines.push_back(line);
        if (end == std::string_view::npos) break;
        text.remove_prefix(end + 1);
    }
    return lines;
}

}  // namespace

std::vector<DiffLine> diff_lines(std::string_view before, std::string_view after) {
    const auto a = split_lines(before);
    const auto b = split_lines(after);
    // Préfixe et suffixe communs mis à part : la table ne couvre que la zone modifiée.
    std::size_t head = 0;
    while (head < a.size() && head < b.size() && a[head] == b[head]) ++head;
    std::size_t tail = 0;
    while (tail < a.size() - head && tail < b.size() - head && a[a.size() - 1 - tail] == b[b.size() - 1 - tail]) ++tail;
    const std::size_t n = a.size() - head - tail;
    const std::size_t m = b.size() - head - tail;

    // lcs[i][j] : longueur de la plus longue sous-suite commune de a[i..] et b[j..] (zone modifiée).
    std::vector<std::uint32_t> lcs((n + 1) * (m + 1), 0);
    auto at = [&](std::size_t i, std::size_t j) -> std::uint32_t& { return lcs[i * (m + 1) + j]; };
    for (std::size_t i = n; i-- > 0;) {
        for (std::size_t j = m; j-- > 0;) {
            at(i, j) = a[head + i] == b[head + j] ? at(i + 1, j + 1) + 1 : std::max(at(i + 1, j), at(i, j + 1));
        }
    }

    std::vector<DiffLine> out;
    for (std::size_t k = 0; k < head; ++k) out.push_back({DiffLine::Kind::same, std::string(a[k])});
    std::size_t i = 0, j = 0;
    std::vector<DiffLine> added;
    auto flush_added = [&] {
        for (auto& line : added) out.push_back(std::move(line));
        added.clear();
    };
    while (i < n || j < m) {
        if (i < n && j < m && a[head + i] == b[head + j]) {
            flush_added();
            out.push_back({DiffLine::Kind::same, std::string(a[head + i])});
            ++i, ++j;
        } else if (j < m && (i == n || at(i, j + 1) >= at(i + 1, j))) {
            added.push_back({DiffLine::Kind::added, std::string(b[head + j++])});
        } else {
            out.push_back({DiffLine::Kind::removed, std::string(a[head + i++])});
        }
    }
    flush_added();
    for (std::size_t k = a.size() - tail; k < a.size(); ++k) out.push_back({DiffLine::Kind::same, std::string(a[k])});
    return out;
}

bool same_lines(const std::vector<DiffLine>& diff) {
    return std::all_of(diff.begin(), diff.end(), [](const DiffLine& l) { return l.kind == DiffLine::Kind::same; });
}

std::string format_diff(const std::vector<DiffLine>& diff, std::size_t context) {
    std::vector<bool> keep(diff.size(), false);
    for (std::size_t k = 0; k < diff.size(); ++k) {
        if (diff[k].kind == DiffLine::Kind::same) continue;
        const std::size_t from = k > context ? k - context : 0;
        const std::size_t to = std::min(diff.size(), k + context + 1);
        for (std::size_t x = from; x < to; ++x) keep[x] = true;
    }
    std::string out;
    bool skipped = false;
    for (std::size_t k = 0; k < diff.size(); ++k) {
        if (!keep[k]) {
            skipped = true;
            continue;
        }
        if (skipped && !out.empty()) out += "…\n";
        skipped = false;
        const char mark = diff[k].kind == DiffLine::Kind::added ? '+' : diff[k].kind == DiffLine::Kind::removed ? '-' : ' ';
        out += mark;
        out += diff[k].text;
        out += '\n';
    }
    return out;
}

}  // namespace tlsrelay
