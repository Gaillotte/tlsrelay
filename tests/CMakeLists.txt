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
    test_frame.cpp
    test_tunnel.cpp
    test_admin.cpp
    test_ca.cpp
    test_attacks.cpp
    test_writer.cpp
    test_crl.cpp
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

# Cycle de vie en console avec le binaire réel (Linux).
if(NOT WIN32)
    add_test(NAME Lifecycle.Console
             COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/lifecycle/console.sh" $<TARGET_FILE:tlsrelay>)
    set_tests_properties(Lifecycle.Console PROPERTIES TIMEOUT 120)
endif()
if(NOT WIN32)
    add_test(NAME Lifecycle.Pki
             COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/lifecycle/pki.sh" $<TARGET_FILE:tlsrelay>)
    set_tests_properties(Lifecycle.Pki PROPERTIES TIMEOUT 180)
    # Refus et cas limites de la ligne de commande, phrase de passe de l'AC (TESTS.md §6.4).
    add_test(NAME Lifecycle.Cli
             COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/lifecycle/cli.sh" $<TARGET_FILE:tlsrelay>)
    set_tests_properties(Lifecycle.Cli PROPERTIES TIMEOUT 180)
endif()
