# Release packages (PLAN, phase 11): .deb and .rpm on Linux, .msi on
# Windows (OpenSSL 3.5 LTS shipped with the application).
#
# Two components: "service" (tlsrelay, documentation, examples) and
# "testkit" (tlsrelay-testkit and acceptance scripts). On Linux, one package
# per component: tlsrelay and tlsrelay-testkit.

# TLSRELAY_DOC_DIR: defined in the top-level CMakeLists.txt (also used by src/admin).

install(FILES README.md LICENSE.txt THIRD-PARTY-NOTICES.txt DESTINATION ${TLSRELAY_DOC_DIR} COMPONENT service)
install(FILES docs/INSTALLATION.md docs/OPERATIONS.md docs/SPEC.md docs/ACCEPTANCE.md docs/ACCEPTANCE-REPORT.md docs/PENTEST.md
        DESTINATION ${TLSRELAY_DOC_DIR} COMPONENT service)
install(DIRECTORY examples/ DESTINATION ${TLSRELAY_DOC_DIR}/examples COMPONENT service)
if(NOT WIN32)
    # Debian: the license goes to /usr/share/doc/<package>/copyright.
    install(FILES LICENSE.txt DESTINATION ${TLSRELAY_DOC_DIR} RENAME copyright COMPONENT service)
endif()

if(WIN32)
    # Dependency DLLs (OpenSSL 3.5, yaml-cpp, spdlog, fmt) and MSVC runtime, next to the executables.
    # vcpkg copies all required DLLs next to the executable (FindOpenSSL does not
    # declare its own as runtime dependencies): take them all.
    install(DIRECTORY "$<TARGET_FILE_DIR:tlsrelay>/" DESTINATION bin COMPONENT service
            FILES_MATCHING PATTERN "*.dll")
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION bin)
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_COMPONENT service)
    include(InstallRequiredSystemLibraries)
    # Acceptance and hardening check on the machine (docs/ACCEPTANCE.md).
    install(FILES tools/acceptance.ps1 tools/acceptance-linux.ps1 tools/check-hardening.ps1 DESTINATION tools COMPONENT testkit)
endif()

set(CPACK_PACKAGE_NAME tlsrelay)
set(CPACK_PACKAGE_VENDOR Gaillotte)
set(CPACK_PACKAGE_CONTACT "Gaillotte (https://github.com/Gaillotte/tlsrelay)")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Plain TCP / TLS 1.3 / mTLS relay")
set(CPACK_PACKAGE_DESCRIPTION
    "tlsrelay relays TCP connections between an application and its destination through a TLS 1.3 "
    "or mTLS tunnel between two instances (client and server): peer whitelist, live PKI rotation, "
    "transparent renegotiation, systemd or Windows service, command-line mini-CA.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/Gaillotte/tlsrelay")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE.txt")
set(CPACK_PACKAGE_INSTALL_DIRECTORY tlsrelay)
set(CPACK_COMPONENTS_ALL service testkit)
if(WIN32 AND TLSRELAY_BUILD_ADMIN)
    # Editor (release 1.1): MSI feature, with Qt (LGPLv3) and a shortcut.
    list(APPEND CPACK_COMPONENTS_ALL admin)
    set(CPACK_COMPONENT_ADMIN_DISPLAY_NAME "tlsrelay-admin")
    set(CPACK_COMPONENT_ADMIN_DESCRIPTION
        "Graphical editor: configuration, whitelist, deployment packages, mini-CA (Qt 6, LGPLv3).")
    set(CPACK_COMPONENT_ADMIN_DEPENDS service)
    set(CPACK_PACKAGE_EXECUTABLES "tlsrelay-admin" "tlsrelay-admin")
endif()
set(CPACK_COMPONENT_SERVICE_DISPLAY_NAME "tlsrelay")
set(CPACK_COMPONENT_SERVICE_DESCRIPTION "tlsrelay service, mini-CA, documentation and configuration examples.")
set(CPACK_COMPONENT_SERVICE_REQUIRED ON)
set(CPACK_COMPONENT_TESTKIT_DISPLAY_NAME "tlsrelay-testkit")
set(CPACK_COMPONENT_TESTKIT_DESCRIPTION "Test and acceptance tooling: echo, load, throughput, latency, network disturbances, test PKI.")
set(CPACK_COMPONENT_TESTKIT_DEPENDS service)

# --- Debian -------------------------------------------------------------------
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_PACKAGE_SECTION net)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
set(CPACK_DEBIAN_SERVICE_PACKAGE_NAME tlsrelay)
set(CPACK_DEBIAN_TESTKIT_PACKAGE_NAME tlsrelay-testkit)
set(CPACK_DEBIAN_SERVICE_PACKAGE_DEPENDS "passwd, systemd")
# The Debian maintainer scripts are kept as *.sh in the sources; CPack takes the
# control file names from the files, so they are copied under their required names.
set(debian_control "")
foreach(script postinst prerm postrm)
    configure_file("${PROJECT_SOURCE_DIR}/packaging/linux/${script}.sh" "${PROJECT_BINARY_DIR}/debian/${script}" COPYONLY)
    list(APPEND debian_control "${PROJECT_BINARY_DIR}/debian/${script}")
endforeach()
set(CPACK_DEBIAN_SERVICE_PACKAGE_CONTROL_EXTRA "${debian_control}")
set(CPACK_DEBIAN_SERVICE_PACKAGE_CONTROL_STRICT_PERMISSION ON)

# --- RPM ----------------------------------------------------------------------
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
set(CPACK_RPM_PACKAGE_LICENSE "LicenseRef-Proprietary")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_URL "https://github.com/Gaillotte/tlsrelay")
set(CPACK_RPM_SERVICE_PACKAGE_NAME tlsrelay)
set(CPACK_RPM_TESTKIT_PACKAGE_NAME tlsrelay-testkit)
set(CPACK_RPM_SERVICE_PACKAGE_REQUIRES "shadow-utils, systemd")
set(CPACK_RPM_TESTKIT_PACKAGE_REQUIRES "tlsrelay = ${PROJECT_VERSION}")
set(CPACK_RPM_SERVICE_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/packaging/linux/rpm-post.sh")
set(CPACK_RPM_SERVICE_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/packaging/linux/rpm-preun.sh")
set(CPACK_RPM_SERVICE_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/packaging/linux/rpm-postun.sh")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /usr/share/doc)

# --- Windows (WiX) ------------------------------------------------------------
set(CPACK_WIX_UPGRADE_GUID "24d7e243-22e9-4987-8ef5-33ee37650b55")  # fixed: in-place upgrades
set(CPACK_WIX_ARCHITECTURE x64)
# Per-machine installation (system service): shortcuts in the common Start
# menu. To be settled before any real installation: changing the scope
# would then prevent in-place upgrades.
set(CPACK_WIX_INSTALL_SCOPE perMachine)
set(CPACK_WIX_PRODUCT_URL "https://github.com/Gaillotte/tlsrelay")

if(WIN32)
    set(CPACK_GENERATOR WIX)
else()
    set(CPACK_GENERATOR DEB RPM)
endif()
include(CPack)
