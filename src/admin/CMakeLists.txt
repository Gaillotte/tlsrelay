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

if(WIN32)
    # DLL et modules d'extension de Qt (windeployqt) à côté de l'exécutable, dans
    # la fonctionnalité « tlsrelay-admin » du MSI. Le runtime MSVC est déjà
    # installé par le composant service (InstallRequiredSystemLibraries).
    qt_generate_deploy_app_script(TARGET tlsrelay-admin OUTPUT_SCRIPT admin_deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR NO_TRANSLATIONS NO_COMPILER_RUNTIME)
    install(SCRIPT "${admin_deploy_script}" COMPONENT admin)
endif()
install(FILES "${PROJECT_SOURCE_DIR}/LICENSES/LGPL-3.0.txt" "${PROJECT_SOURCE_DIR}/LICENSES/GPL-3.0.txt"
        DESTINATION ${TLSRELAY_DOC_DIR}/LICENSES COMPONENT admin)
install(FILES "${PROJECT_SOURCE_DIR}/docs/EDITEUR.md" DESTINATION ${TLSRELAY_DOC_DIR} COMPONENT admin)

if(TLSRELAY_BUILD_TESTS)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    add_executable(tlsrelay_admin_tests
        "${PROJECT_SOURCE_DIR}/tests/admin/test_admin.cpp")
    target_link_libraries(tlsrelay_admin_tests PRIVATE tlsrelay_admin_lib tlsrelay::options Qt6::Test
        yaml-cpp::yaml-cpp)
    target_compile_definitions(tlsrelay_admin_tests PRIVATE
        TLSRELAY_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples")
    add_test(NAME Admin.QtTests COMMAND tlsrelay_admin_tests)
    # Contrôle sans fenêtre (--check) : exemple valide, fichier invalide.
    add_test(NAME Admin.CheckValid COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/examples/client.yaml")
    add_test(NAME Admin.CheckInvalid COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/tests/admin/invalide.yaml")
    # Le diagnostic attendu, et non un simple code d'échec (qui couvrirait un plantage).
    set_tests_properties(Admin.CheckInvalid PROPERTIES PASS_REGULAR_EXPRESSION "ports.plain.listen : adresse invalide")
    # Liste blanche invalide derrière une configuration valide ; fichier absent.
    add_test(NAME Admin.CheckWhitelist
             COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/tests/admin/serveur-liste-invalide.yaml")
    set_tests_properties(Admin.CheckWhitelist PROPERTIES PASS_REGULAR_EXPRESSION "liste-invalide.yaml : peers\\[0\\]\\.ip")
    add_test(NAME Admin.CheckUnreadable COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/tests/admin/absent.yaml")
    set_tests_properties(Admin.CheckUnreadable PROPERTIES PASS_REGULAR_EXPRESSION "absent.yaml : fichier illisible")
    # Sans affichage : plateforme Qt « offscreen ».
    set_tests_properties(Admin.QtTests Admin.CheckValid Admin.CheckInvalid Admin.CheckWhitelist Admin.CheckUnreadable PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
endif()
