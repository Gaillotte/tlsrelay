# Dépendances embarquées (TLSRELAY_FETCH_DEPS) pour les paquets Linux : les
# bibliothèques des distributions visées (Ubuntu 22.04, RHEL 9) sont trop
# anciennes (Asio sans opérateurs d'awaitable, notamment). Versions fixées par
# leur commit (intégrité garantie par git), liées statiquement ; seul OpenSSL
# reste celui de la distribution.

include(FetchContent)

FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG 12e0ce9e0500bf0f247dbd1ae894272656456079  # asio-1-30-2
    SOURCE_SUBDIR sans-cmake)                          # en-têtes seulement
FetchContent_Declare(cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG 6c7b07a878ad834957b98d0f9ce1dbe0cb204fc9)  # v2.4.2
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG 27cb4c76708608465c413f6d0e6b8d99a4d84302)  # v1.14.1 (fmt intégré)
FetchContent_Declare(yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG f7320141120f720aecc4c32be25586e7da9eb978)  # 0.8.0

set(BUILD_SHARED_LIBS OFF)
set(CLI11_PRECOMPILED OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(CLI11_INSTALL OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(asio cli11 spdlog yaml-cpp)

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)
add_library(asio::asio INTERFACE IMPORTED)
target_include_directories(asio::asio SYSTEM INTERFACE "${asio_SOURCE_DIR}/asio/include")
target_link_libraries(asio::asio INTERFACE Threads::Threads)

# En-têtes des dépendances traités comme externes (pas d'avertissements du projet).
foreach(target spdlog yaml-cpp CLI11)
    if(TARGET ${target})
        get_target_property(dirs ${target} INTERFACE_INCLUDE_DIRECTORIES)
        set_target_properties(${target} PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${dirs}")
    endif()
endforeach()

if(TLSRELAY_BUILD_TESTS)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG f8d7d77c06936315286eb55f8de22cd23c188571)  # v1.14.0
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()
