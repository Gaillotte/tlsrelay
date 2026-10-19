#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace tlsrelay {

using Duration = std::chrono::milliseconds;

// Duration in the format <integer><unit>, units: ms, s, m, h, d. Example: "30s", "5m".
std::optional<Duration> parse_duration(std::string_view text);

// Size in the format <integer>[unit], units: B, KiB, MiB, GiB. Without a unit: bytes.
std::optional<std::uint64_t> parse_size(std::string_view text);

// Percentage in the format <number>%, between 0 and 100. Returns a fraction (10% -> 0.1).
std::optional<double> parse_percent(std::string_view text);

// Readable form of a duration, with the largest unit that represents it exactly.
std::string format_duration(Duration d);

// Readable form of a size, with the largest unit that represents it exactly ("4MiB").
std::string format_size(std::uint64_t bytes);

// Readable form of a fraction as a percentage (0.1 -> "10%"), read back identically by parse_percent.
std::string format_percent(double fraction);

}  // namespace tlsrelay
