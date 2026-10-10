#include "tlsrelay/endpoint.hpp"

#include <gtest/gtest.h>

using namespace tlsrelay;

TEST(ParseEndpoint, AcceptsIpv4HostnameAndIpv6) {
    EXPECT_EQ(parse_endpoint("127.0.0.1:9001"), (Endpoint{"127.0.0.1", 9001}));
    EXPECT_EQ(parse_endpoint("relay.example:443"), (Endpoint{"relay.example", 443}));
    EXPECT_EQ(parse_endpoint("[::1]:7001"), (Endpoint{"::1", 7001}));
    EXPECT_EQ(parse_endpoint("[2001:db8::5]:65535"), (Endpoint{"2001:db8::5", 65535}));
    EXPECT_EQ(parse_endpoint("0.0.0.0:0"), (Endpoint{"0.0.0.0", 0}));
}

TEST(ParseEndpoint, RejectsInvalidInput) {
    for (const char* text : {"", "127.0.0.1", ":80", "host:", "host:65536", "host:-1", "host:80x", "::1:80",
                             "[::1]", "[::1]80", "[relay.example]:80", "[127.0.0.1]:80"}) {
        EXPECT_FALSE(parse_endpoint(text).has_value()) << text;
    }
}

TEST(Endpoint, ToStringBracketsIpv6) {
    EXPECT_EQ((Endpoint{"::1", 7001}).to_string(), "[::1]:7001");
    EXPECT_EQ((Endpoint{"10.0.0.1", 80}).to_string(), "10.0.0.1:80");
}

TEST(IpLiteral, RecognisesAddresses) {
    EXPECT_TRUE(is_ip_literal("10.0.0.1"));
    EXPECT_TRUE(is_ip_literal("::1"));
    EXPECT_FALSE(is_ip_literal("relay.example"));
    EXPECT_FALSE(is_ip_literal("300.0.0.1"));
    EXPECT_TRUE(is_wildcard_address("0.0.0.0"));
    EXPECT_TRUE(is_wildcard_address("::"));
    EXPECT_FALSE(is_wildcard_address("127.0.0.1"));
}
