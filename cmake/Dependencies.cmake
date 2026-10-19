# External dependencies. On Windows, they are provided by vcpkg (vcpkg.json);
# on Linux, by the distribution packages or by vcpkg.

find_package(OpenSSL 3.0 REQUIRED)
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
