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
option(TLSRELAY_FUZZ "Compiler les cibles de fuzzing libFuzzer (clang)" OFF)
option(TLSRELAY_WARNINGS_AS_ERRORS "Traiter les avertissements comme des erreurs" OFF)
option(TLSRELAY_MSVC_ANALYZE "Analyse statique MSVC (/analyze) du code du projet" OFF)
option(TLSRELAY_BUILD_ADMIN "Compiler l'éditeur tlsrelay-admin (Qt 6)" OFF)
option(TLSRELAY_COVERAGE "Instrumenter le code pour la mesure de couverture (GCC/Clang, gcov)" OFF)
option(TLSRELAY_FETCH_DEPS "Dépendances embarquées (Asio, CLI11, spdlog, yaml-cpp), liées statiquement" OFF)
set(TLSRELAY_SANITIZERS "" CACHE STRING "Sanitizers à activer (ex. address,undefined), GCC/Clang uniquement")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerOptions)

# Emplacement de la documentation installée (paquets).
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

# Après enable_testing() : les tests Qt de l'éditeur s'enregistrent dans CTest.
if(TLSRELAY_BUILD_ADMIN)
    add_subdirectory(src/admin)
endif()

include(Packaging)
