#include "tlsrelay/units.hpp"

#include <array>
#include <charconv>
#include <limits>
#include <utility>

namespace tlsrelay {
namespace {

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

// Sépare la partie numérique entière de son suffixe.
std::optional<std::pair<std::uint64_t, std::string_view>> split_number(std::string_view text) {
    text = trim(text);
    std::uint64_t value = 0;
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end == text.data()) return std::nullopt;
    return std::pair{value, std::string_view(end, static_cast<std::size_t>(text.data() + text.size() - end))};
}

std::optional<std::uint64_t> checked_mul(std::uint64_t a, std::uint64_t b) {
    if (b != 0 && a > std::numeric_limits<std::uint64_t>::max() / b) return std::nullopt;
    return a * b;
}

}  // namespace

std::optional<Duration> parse_duration(std::string_view text) {
    auto parts = split_number(text);
    if (!parts) return std::nullopt;
    auto [value, unit] = *parts;

    static constexpr std::array<std::pair<std::string_view, std::uint64_t>, 5> kUnits{{
        {"ms", 1}, {"s", 1000}, {"m", 60'000}, {"h", 3'600'000}, {"d", 86'400'000}}};
    for (const auto& [name, factor] : kUnits) {
        if (unit != name) continue;
        auto ms = checked_mul(value, factor);
        if (!ms || *ms > static_cast<std::uint64_t>(std::numeric_limits<Duration::rep>::max())) return std::nullopt;
        return Duration(static_cast<Duration::rep>(*ms));
    }
    return std::nullopt;
}

std::optional<std::uint64_t> parse_size(std::string_view text) {
    auto parts = split_number(text);
    if (!parts) return std::nullopt;
    auto [value, unit] = *parts;

    static constexpr std::array<std::pair<std::string_view, std::uint64_t>, 5> kUnits{{
        {"", 1}, {"B", 1}, {"KiB", 1ULL << 10}, {"MiB", 1ULL << 20}, {"GiB", 1ULL << 30}}};
    for (const auto& [name, factor] : kUnits) {
        if (unit == name) return checked_mul(value, factor);
    }
    return std::nullopt;
}

std::optional<double> parse_percent(std::string_view text) {
    text = trim(text);
    if (text.size() < 2 || text.back() != '%') return std::nullopt;
    text.remove_suffix(1);
    double value = 0;
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    if (!(value >= 0.0 && value <= 100.0)) return std::nullopt;
    return value / 100.0;
}

std::string format_size(std::uint64_t bytes) {
    static constexpr std::array<std::pair<std::string_view, std::uint64_t>, 3> kUnits{{
        {"GiB", 1ULL << 30}, {"MiB", 1ULL << 20}, {"KiB", 1ULL << 10}}};
    if (bytes != 0) {
        for (const auto& [name, factor] : kUnits) {
            if (bytes % factor == 0) return std::to_string(bytes / factor) + std::string(name);
        }
    }
    return std::to_string(bytes);
}

std::string format_percent(double fraction) {
    // Écriture la plus courte qui redonne exactement la même fraction.
    char buffer[64];
    for (int precision = 0; precision <= 17; ++precision) {
        auto [end, ec] = std::to_chars(buffer, buffer + sizeof buffer, fraction * 100.0, std::chars_format::fixed,
                                       precision);
        if (ec != std::errc{}) break;
        std::string text(buffer, end);
        text += '%';
        if (auto back = parse_percent(text); back && *back == fraction) return text;
    }
    auto [end, ec] = std::to_chars(buffer, buffer + sizeof buffer, fraction * 100.0);
    return std::string(buffer, ec == std::errc{} ? end : buffer) + "%";
}

std::string format_duration(Duration d) {
    const auto ms = d.count();
    static constexpr std::array<std::pair<std::string_view, Duration::rep>, 4> kUnits{{
        {"d", 86'400'000}, {"h", 3'600'000}, {"m", 60'000}, {"s", 1000}}};
    if (ms != 0) {
        for (const auto& [name, factor] : kUnits) {
            if (ms % factor == 0) return std::to_string(ms / factor) + std::string(name);
        }
    }
    return std::to_string(ms) + "ms";
}

}  // namespace tlsrelay
