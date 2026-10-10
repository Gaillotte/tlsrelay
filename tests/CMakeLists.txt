add_executable(tlsrelay_tests
    test_units.cpp
    test_endpoint.cpp
    test_config.cpp
    test_logging.cpp
    test_relay.cpp)

target_link_libraries(tlsrelay_tests PRIVATE
    tlsrelay::core tlsrelay::options
    OpenSSL::Crypto
    GTest::gtest GTest::gtest_main)

target_compile_definitions(tlsrelay_tests PRIVATE
    TLSRELAY_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples")

include(GoogleTest)
gtest_discover_tests(tlsrelay_tests
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT 60
    PROPERTIES TIMEOUT 60)
