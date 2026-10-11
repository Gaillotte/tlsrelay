configure_file(version.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/generated/tlsrelay/version.hpp" @ONLY)

add_library(tlsrelay_core STATIC
    src/units.cpp
    src/endpoint.cpp
    src/config.cpp
    src/logging.cpp
    src/openssl_info.cpp
    src/tls/openssl_ptr.cpp
    src/tls/context.cpp
    src/pki/generation.cpp
    src/relay/stream.cpp
    src/relay/dial.cpp
    src/relay/channel.cpp
    src/relay/service.cpp)
add_library(tlsrelay::core ALIAS tlsrelay_core)

target_include_directories(tlsrelay_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/generated")

target_compile_definitions(tlsrelay_core PUBLIC ASIO_STANDALONE ASIO_NO_DEPRECATED)

target_link_libraries(tlsrelay_core
    PUBLIC
        asio::asio
        spdlog::spdlog
        OpenSSL::SSL
        OpenSSL::Crypto
    PRIVATE
        tlsrelay::options
        yaml-cpp::yaml-cpp)

if(WIN32)
    target_link_libraries(tlsrelay_core PUBLIC ws2_32 mswsock)
endif()
