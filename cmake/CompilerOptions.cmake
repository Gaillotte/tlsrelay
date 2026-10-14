# Options de compilation communes : avertissements, durcissement, sanitizers.
# Toutes les cibles du projet se lient à tlsrelay::options.

include(CheckPIESupported)
check_pie_supported()

add_library(tlsrelay_options INTERFACE)
add_library(tlsrelay::options ALIAS tlsrelay_options)

if(MSVC)
    target_compile_options(tlsrelay_options INTERFACE
        /W4 /permissive- /utf-8 /EHsc /Zc:__cplusplus
        /sdl /guard:cf)
    target_link_options(tlsrelay_options INTERFACE
        /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
    # Windows 10 minimum ; évite les macros min/max de windows.h.
    target_compile_definitions(tlsrelay_options INTERFACE
        _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
    if(TLSRELAY_WARNINGS_AS_ERRORS)
        target_compile_options(tlsrelay_options INTERFACE /WX)
    endif()
    if(TLSRELAY_MSVC_ANALYZE)
        # Code du projet seulement : les en-têtes des dépendances (inclusions
        # système de vcpkg) ne sont ni analysés ni signalés.
        target_compile_options(tlsrelay_options INTERFACE
            /analyze /analyze:external- /external:anglebrackets /external:W0)
    endif()
else()
    target_compile_options(tlsrelay_options INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor
        -fstack-protector-strong
        $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2>)
    if(NOT APPLE)
        target_link_options(tlsrelay_options INTERFACE -Wl,-z,relro,-z,now)
    endif()
    if(TLSRELAY_WARNINGS_AS_ERRORS)
        target_compile_options(tlsrelay_options INTERFACE -Werror)
    endif()
    # GCC 12 (paquets Ubuntu 22.04) : faux positif -Wrestrict sur « littéral + std::string »
    # (bogue GCC 105329, corrigé dans GCC 13).
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12
       AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13)
        target_compile_options(tlsrelay_options INTERFACE -Wno-restrict)
    endif()
    if(TLSRELAY_SANITIZERS)
        target_compile_options(tlsrelay_options INTERFACE
            -fsanitize=${TLSRELAY_SANITIZERS} -fno-omit-frame-pointer -fno-sanitize-recover=all)
        target_link_options(tlsrelay_options INTERFACE -fsanitize=${TLSRELAY_SANITIZERS})
    endif()
    if(TLSRELAY_COVERAGE)
        # Mesure de couverture (gcov) : sans optimisation pour que lignes et branches
        # correspondent au source ; rapport par tools/coverage.sh.
        target_compile_options(tlsrelay_options INTERFACE --coverage -O0 -fprofile-update=atomic)
        target_link_options(tlsrelay_options INTERFACE --coverage)
    endif()
endif()
