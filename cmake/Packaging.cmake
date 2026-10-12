# Paquets de la livraison (PLAN, phase 11) : .deb et .rpm sous Linux, .msi sous
# Windows (OpenSSL 3.5 LTS livré avec l'application).
#
# Deux composants : « service » (tlsrelay, documentation, exemples) et
# « testkit » (tlsrelay-testkit et scripts de recette). Sous Linux, un paquet
# par composant : tlsrelay et tlsrelay-testkit.

include(GNUInstallDirs)

if(WIN32)
    set(TLSRELAY_DOC_DIR doc)
else()
    set(TLSRELAY_DOC_DIR ${CMAKE_INSTALL_DOCDIR})
endif()

install(FILES README.md LICENSE THIRD-PARTY-NOTICES.txt DESTINATION ${TLSRELAY_DOC_DIR} COMPONENT service)
install(FILES docs/INSTALLATION.md docs/EXPLOITATION.md docs/SPEC.md docs/RECETTE.md docs/PV-RECETTE.md docs/PENTEST.md
        DESTINATION ${TLSRELAY_DOC_DIR} COMPONENT service)
install(DIRECTORY examples/ DESTINATION ${TLSRELAY_DOC_DIR}/examples COMPONENT service)
if(NOT WIN32)
    # Debian : la licence va dans /usr/share/doc/<paquet>/copyright.
    install(FILES LICENSE DESTINATION ${TLSRELAY_DOC_DIR} RENAME copyright COMPONENT service)
endif()

if(WIN32)
    # DLL des dépendances (OpenSSL 3.5, yaml-cpp, spdlog, fmt) et runtime MSVC, à côté des exécutables.
    # vcpkg copie toutes les DLL nécessaires à côté de l'exécutable (FindOpenSSL ne
    # déclare pas les siennes comme dépendances d'exécution) : on les reprend toutes.
    install(DIRECTORY "$<TARGET_FILE_DIR:tlsrelay>/" DESTINATION bin COMPONENT service
            FILES_MATCHING PATTERN "*.dll")
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION bin)
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_COMPONENT service)
    include(InstallRequiredSystemLibraries)
    # Recette et vérification du durcissement sur le poste (docs/RECETTE.md).
    install(FILES tools/recette.ps1 tools/recette-linux.ps1 tools/check-hardening.ps1 DESTINATION tools COMPONENT testkit)
endif()

set(CPACK_PACKAGE_NAME tlsrelay)
set(CPACK_PACKAGE_VENDOR Gaillotte)
set(CPACK_PACKAGE_CONTACT "Gaillotte (https://github.com/Gaillotte/tlsrelay)")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Relais TCP clair / TLS 1.3 / mTLS")
set(CPACK_PACKAGE_DESCRIPTION
    "tlsrelay relaie des connexions TCP entre une application et sa destination à travers un tunnel TLS 1.3 "
    "ou mTLS entre deux instances (client et serveur) : liste blanche des pairs, rotation à chaud de la PKI, "
    "renégociation transparente, service systemd ou Windows, mini-AC en ligne de commande.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/Gaillotte/tlsrelay")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
# WiX n'accepte qu'une licence .txt ou .rtf : copie avec extension.
configure_file("${PROJECT_SOURCE_DIR}/LICENSE" "${PROJECT_BINARY_DIR}/LICENSE.txt" COPYONLY)
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_BINARY_DIR}/LICENSE.txt")
set(CPACK_PACKAGE_INSTALL_DIRECTORY tlsrelay)
set(CPACK_COMPONENTS_ALL service testkit)
set(CPACK_COMPONENT_SERVICE_DISPLAY_NAME "tlsrelay")
set(CPACK_COMPONENT_SERVICE_DESCRIPTION "Service tlsrelay, mini-AC, documentation et exemples de configuration.")
set(CPACK_COMPONENT_SERVICE_REQUIRED ON)
set(CPACK_COMPONENT_TESTKIT_DISPLAY_NAME "tlsrelay-testkit")
set(CPACK_COMPONENT_TESTKIT_DESCRIPTION "Outillage de test et de recette : écho, charge, débit, latence, perturbations réseau, PKI de test.")
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
set(CPACK_DEBIAN_SERVICE_PACKAGE_CONTROL_EXTRA
    "${PROJECT_SOURCE_DIR}/packaging/linux/postinst;${PROJECT_SOURCE_DIR}/packaging/linux/prerm;${PROJECT_SOURCE_DIR}/packaging/linux/postrm")
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
set(CPACK_WIX_UPGRADE_GUID "24d7e243-22e9-4987-8ef5-33ee37650b55")  # fixe : mises à jour en place
set(CPACK_WIX_ARCHITECTURE x64)
set(CPACK_WIX_PRODUCT_URL "https://github.com/Gaillotte/tlsrelay")

if(WIN32)
    set(CPACK_GENERATOR WIX)
else()
    set(CPACK_GENERATOR DEB RPM)
endif()
include(CPack)
