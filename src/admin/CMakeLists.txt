# Éditeur tlsrelay-admin (livraison 1.1) : Qt 6 Widgets, liaison dynamique (LGPLv3).
find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets)

set(CMAKE_AUTOMOC ON)

# Bibliothèque de l'éditeur : partagée par l'exécutable et les tests Qt.
add_library(tlsrelay_admin_lib STATIC
    config_form.cpp
    whitelist_editor.cpp
    diff_dialog.cpp
    export_dialog.cpp
    main_window.cpp
    deployment.cpp
    document.cpp
    pki_panel.cpp
    sign_dialog.cpp)
target_include_directories(tlsrelay_admin_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(tlsrelay_admin_lib
    PUBLIC tlsrelay::core Qt6::Widgets
    PRIVATE tlsrelay::options yaml-cpp::yaml-cpp)

add_executable(tlsrelay-admin WIN32 main.cpp)
target_link_libraries(tlsrelay-admin PRIVATE tlsrelay_admin_lib tlsrelay::options)
install(TARGETS tlsrelay-admin RUNTIME DESTINATION bin COMPONENT admin)

if(TLSRELAY_BUILD_TESTS)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    add_executable(tlsrelay_admin_tests
        "${PROJECT_SOURCE_DIR}/tests/admin/test_admin.cpp")
    target_link_libraries(tlsrelay_admin_tests PRIVATE tlsrelay_admin_lib tlsrelay::options Qt6::Test
        yaml-cpp::yaml-cpp)
    target_compile_definitions(tlsrelay_admin_tests PRIVATE
        TLSRELAY_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples")
    add_test(NAME Admin.QtTests COMMAND tlsrelay_admin_tests)
    # Sans affichage : plateforme Qt « offscreen ».
    set_tests_properties(Admin.QtTests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
endif()
