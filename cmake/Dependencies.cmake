# External dependencies. On Linux, they come from the distribution packages (or
# vcpkg). On Windows, from vcpkg (vcpkg.json), except OpenSSL 3.5 LTS, built from
# the official release by tools/build-openssl.ps1 (OPENSSL_ROOT_DIR, set by the
# windows-msvc preset to build/openssl).

if(WIN32)
    find_package(OpenSSL 3.5)
    if(NOT OPENSSL_FOUND)
        message(FATAL_ERROR "OpenSSL 3.5 not found (OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}): "
                            "run tools/build-openssl.ps1 first (docs/BUILD-WINDOWS.md)")
    endif()
    # The OpenSSL DLLs are copied next to each executable (tests, build-tree runs, installation).
    get_filename_component(TLSRELAY_OPENSSL_ROOT "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
    file(GLOB TLSRELAY_OPENSSL_DLLS "${TLSRELAY_OPENSSL_ROOT}/bin/libcrypto-*.dll" "${TLSRELAY_OPENSSL_ROOT}/bin/libssl-*.dll")
    if(NOT TLSRELAY_OPENSSL_DLLS)
        message(FATAL_ERROR "OpenSSL DLLs not found in ${TLSRELAY_OPENSSL_ROOT}/bin")
    endif()
else()
    find_package(OpenSSL 3.0 REQUIRED)
endif()
find_package(yaml-cpp CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

# Standalone Asio: vcpkg provides asio::asio; the Linux packages (libasio-dev)
# only provide the headers.
find_package(asio CONFIG QUIET)
if(NOT TARGET asio::asio)
    find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)
    add_library(asio::asio INTERFACE IMPORTED)
    target_include_directories(asio::asio SYSTEM INTERFACE "${ASIO_INCLUDE_DIR}")
    find_package(Threads REQUIRED)
    target_link_libraries(asio::asio INTERFACE Threads::Threads)
endif()

if(TLSRELAY_BUILD_TESTS)
    find_package(GTest CONFIG QUIET)
    if(NOT TARGET GTest::gtest)
        find_package(GTest REQUIRED)
    endif()
endif()
