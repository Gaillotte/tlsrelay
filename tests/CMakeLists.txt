add_executable(tlsrelay_tests
    test_units.cpp
    test_endpoint.cpp
    test_config.cpp
    test_logging.cpp
    test_relay.cpp
    test_pki.cpp
    test_tls.cpp
    test_whitelist.cpp
    test_mtls.cpp
    test_rotation.cpp
    support/test_pki.cpp)

target_link_libraries(tlsrelay_tests PRIVATE
    tlsrelay::core tlsrelay::options
    OpenSSL::SSL
    OpenSSL::Crypto
    GTest::gtest GTest::gtest_main)

target_include_directories(tlsrelay_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

target_compile_definitions(tlsrelay_tests PRIVATE
    TLSRELAY_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples")

include(GoogleTest)
gtest_discover_tests(tlsrelay_tests
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT 60
    PROPERTIES TIMEOUT 60)
