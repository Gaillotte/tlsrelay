# tlsrelay-admin editor (release 1.1): Qt 6 Widgets, dynamic linking (LGPLv3).
find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets)

set(CMAKE_AUTOMOC ON)

# Editor library: shared by the executable and the Qt tests.
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

# Editor tour for the demonstration video (tools/video): excluded from the
# default build, never installed.
add_executable(tlsrelay-admin-tour EXCLUDE_FROM_ALL "${PROJECT_SOURCE_DIR}/tools/video/editor_tour.cpp")
target_include_directories(tlsrelay-admin-tour PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(tlsrelay-admin-tour PRIVATE tlsrelay_admin_lib tlsrelay::options)
target_link_libraries(tlsrelay-admin PRIVATE tlsrelay_admin_lib tlsrelay::options)
install(TARGETS tlsrelay-admin RUNTIME DESTINATION bin COMPONENT admin)

if(WIN32)
    # Qt DLLs and plugins (windeployqt) next to the executable, in the
    # "tlsrelay-admin" feature of the MSI. The MSVC runtime is already
    # installed by the service component (InstallRequiredSystemLibraries).
    qt_generate_deploy_app_script(TARGET tlsrelay-admin OUTPUT_SCRIPT admin_deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR NO_TRANSLATIONS NO_COMPILER_RUNTIME)
    install(SCRIPT "${admin_deploy_script}" COMPONENT admin)
endif()
install(FILES "${PROJECT_SOURCE_DIR}/LICENSES/LGPL-3.0.txt" "${PROJECT_SOURCE_DIR}/LICENSES/GPL-3.0.txt"
        DESTINATION ${TLSRELAY_DOC_DIR}/LICENSES COMPONENT admin)
install(FILES "${PROJECT_SOURCE_DIR}/docs/EDITOR.md" DESTINATION ${TLSRELAY_DOC_DIR} COMPONENT admin)

if(TLSRELAY_BUILD_TESTS)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    add_executable(tlsrelay_admin_tests
        "${PROJECT_SOURCE_DIR}/tests/admin/test_admin.cpp")
    target_link_libraries(tlsrelay_admin_tests PRIVATE tlsrelay_admin_lib tlsrelay::options Qt6::Test
        yaml-cpp::yaml-cpp)
    target_compile_definitions(tlsrelay_admin_tests PRIVATE
        TLSRELAY_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/examples")
    add_test(NAME Admin.QtTests COMMAND tlsrelay_admin_tests)
    # Check without a window (--check): valid example, invalid file.
    add_test(NAME Admin.CheckValid COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/examples/client.yaml")
    add_test(NAME Admin.CheckInvalid COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/tests/admin/invalid.yaml")
    # The expected diagnostic, not just a failure code (which would also cover a crash).
    set_tests_properties(Admin.CheckInvalid PROPERTIES PASS_REGULAR_EXPRESSION "ports.plain.listen: invalid address")
    # Invalid whitelist behind a valid configuration; missing file.
    add_test(NAME Admin.CheckWhitelist
             COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/tests/admin/server-invalid-whitelist.yaml")
    set_tests_properties(Admin.CheckWhitelist PROPERTIES PASS_REGULAR_EXPRESSION "invalid-whitelist.yaml: peers\\[0\\]\\.ip")
    add_test(NAME Admin.CheckUnreadable COMMAND tlsrelay-admin --check "${PROJECT_SOURCE_DIR}/tests/admin/absent.yaml")
    set_tests_properties(Admin.CheckUnreadable PROPERTIES PASS_REGULAR_EXPRESSION "absent.yaml: unreadable file")
    # --check on a machine without a display (Linux server): no Qt variable, no DISPLAY.
    if(NOT WIN32)
        add_test(NAME Admin.CheckHeadless
                 COMMAND ${CMAKE_COMMAND} -E env --unset=DISPLAY --unset=WAYLAND_DISPLAY --unset=QT_QPA_PLATFORM
                         $<TARGET_FILE:tlsrelay-admin> --check "${PROJECT_SOURCE_DIR}/examples/client.yaml")
        set_tests_properties(Admin.CheckHeadless PROPERTIES PASS_REGULAR_EXPRESSION "client.yaml: valid" TIMEOUT 60)
    endif()
    # Without a display: Qt "offscreen" platform.
    set_tests_properties(Admin.QtTests Admin.CheckValid Admin.CheckInvalid Admin.CheckWhitelist Admin.CheckUnreadable PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
endif()
