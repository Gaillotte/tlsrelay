#include "tlsrelay/units.hpp"

#include <gtest/gtest.h>

using namespace tlsrelay;
using namespace std::chrono_literals;

TEST(ParseDuration, AcceptsAllUnits) {
    EXPECT_EQ(parse_duration("500ms"), Duration(500));
    EXPECT_EQ(parse_duration("30s"), Duration(30s));
    EXPECT_EQ(parse_duration("5m"), Duration(5min));
    EXPECT_EQ(parse_duration("1h"), Duration(1h));
    EXPECT_EQ(parse_duration("30d"), Duration(std::chrono::days(30)));
    EXPECT_EQ(parse_duration(" 10s "), Duration(10s));
    EXPECT_EQ(parse_duration("0s"), Duration(0));
}

TEST(ParseDuration, RejectsInvalidInput) {
    for (const char* text : {"", "10", "s", "10x", "-5s", "1.5s", "10 s", "10sec", "abc"}) {
        EXPECT_FALSE(parse_duration(text).has_value()) << text;
    }
}

TEST(ParseDuration, RejectsOverflow) {
    EXPECT_FALSE(parse_duration("99999999999999999999d").has_value());
    EXPECT_FALSE(parse_duration("999999999999999999d").has_value());
}

TEST(ParseSize, AcceptsUnitsAndPlainBytes) {
    EXPECT_EQ(parse_size("65536"), 65536u);
    EXPECT_EQ(parse_size("10B"), 10u);
    EXPECT_EQ(parse_size("64KiB"), 64u * 1024);
    EXPECT_EQ(parse_size("4MiB"), 4u * 1024 * 1024);
    EXPECT_EQ(parse_size("1GiB"), 1ULL << 30);
}

TEST(ParseSize, RejectsInvalidInput) {
    for (const char* text : {"", "MiB", "4MB", "4mib", "-1", "1.5MiB"}) {
        EXPECT_FALSE(parse_size(text).has_value()) << text;
    }
}

TEST(ParsePercent, ReturnsFraction) {
    EXPECT_DOUBLE_EQ(*parse_percent("10%"), 0.10);
    EXPECT_DOUBLE_EQ(*parse_percent("12.5%"), 0.125);
    EXPECT_DOUBLE_EQ(*parse_percent("0%"), 0.0);
    EXPECT_DOUBLE_EQ(*parse_percent("100%"), 1.0);
}

TEST(ParsePercent, RejectsInvalidInput) {
    for (const char* text : {"", "%", "10", "101%", "-1%", "abc%", "10 %"}) {
        EXPECT_FALSE(parse_percent(text).has_value()) << text;
    }
}

TEST(FormatDuration, UsesLargestExactUnit) {
    EXPECT_EQ(format_duration(Duration(30s)), "30s");
    EXPECT_EQ(format_duration(Duration(90s)), "90s");
    EXPECT_EQ(format_duration(Duration(5min)), "5m");
    EXPECT_EQ(format_duration(Duration(1500)), "1500ms");
    EXPECT_EQ(format_duration(Duration(0)), "0ms");
    EXPECT_EQ(format_duration(Duration(std::chrono::days(2))), "2d");
}
