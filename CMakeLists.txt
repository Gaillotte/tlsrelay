cmake_minimum_required(VERSION 3.25)

project(tlsrelay
    VERSION 0.1.0
    DESCRIPTION "Relais TCP clair / TLS 1.3 / mTLS"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TLSRELAY_BUILD_TESTS "Compiler les tests" ON)
option(TLSRELAY_WARNINGS_AS_ERRORS "Traiter les avertissements comme des erreurs" OFF)
set(TLSRELAY_SANITIZERS "" CACHE STRING "Sanitizers à activer (ex. address,undefined), GCC/Clang uniquement")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerOptions)
include(Dependencies)

add_subdirectory(src/core)
add_subdirectory(src/app)

if(TLSRELAY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
