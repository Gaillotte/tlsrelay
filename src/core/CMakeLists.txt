configure_file(version.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/generated/tlsrelay/version.hpp" @ONLY)

add_library(tlsrelay_core STATIC
    src/units.cpp
    src/endpoint.cpp
    src/config.cpp
    src/whitelist.cpp
    src/logging.cpp
    src/openssl_info.cpp
    src/tls/openssl_ptr.cpp
    src/tls/context.cpp
    src/pki/generation.cpp
    src/pki/request.cpp
    src/pki/authority.cpp
    src/tunnel/frame.cpp
    src/relay/stream.cpp
    src/relay/dial.cpp
    src/relay/transport.cpp
    src/relay/channel.cpp
    src/relay/service.cpp
    src/admin/admin.cpp
    src/system/notify.cpp)
if(WIN32)
    target_sources(tlsrelay_core PRIVATE src/admin/windows.cpp)
else()
    target_sources(tlsrelay_core PRIVATE src/admin/posix.cpp)
endif()
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
    target_link_libraries(tlsrelay_core PUBLIC ws2_32 mswsock advapi32)
endif()
