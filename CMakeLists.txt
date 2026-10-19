cmake_minimum_required(VERSION 3.25)

project(tlsrelay
    VERSION 0.1.0
    DESCRIPTION "Plain TCP / TLS 1.3 / mTLS relay"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TLSRELAY_BUILD_TESTS "Build the tests" ON)
option(TLSRELAY_FUZZ "Build the libFuzzer fuzzing targets (clang)" OFF)
option(TLSRELAY_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(TLSRELAY_MSVC_ANALYZE "MSVC static analysis (/analyze) of the project code" OFF)
option(TLSRELAY_BUILD_ADMIN "Build the tlsrelay-admin editor (Qt 6)" OFF)
option(TLSRELAY_COVERAGE "Instrument the code for coverage measurement (GCC/Clang, gcov)" OFF)
option(TLSRELAY_FETCH_DEPS "Bundled dependencies (Asio, CLI11, spdlog, yaml-cpp), linked statically" OFF)
set(TLSRELAY_SANITIZERS "" CACHE STRING "Sanitizers to enable (e.g. address,undefined), GCC/Clang only")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerOptions)

# Location of the installed documentation (packages).
include(GNUInstallDirs)
if(WIN32)
    set(TLSRELAY_DOC_DIR doc)
else()
    set(TLSRELAY_DOC_DIR ${CMAKE_INSTALL_DOCDIR})
endif()
if(TLSRELAY_FETCH_DEPS)
    include(FetchDependencies)
else()
    include(Dependencies)
endif()

add_subdirectory(src/core)
add_subdirectory(src/app)
add_subdirectory(src/testkit)

if(TLSRELAY_FUZZ)
    add_subdirectory(fuzz)
endif()

if(TLSRELAY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# After enable_testing(): the editor's Qt tests register with CTest.
if(TLSRELAY_BUILD_ADMIN)
    add_subdirectory(src/admin)
endif()

include(Packaging)
