### GENERAL SETTINGS
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The SSH Library")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_PACKAGE_VENDOR "The SSH Library Development Team")
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")

set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

# SOURCE GENERATOR
set(CPACK_SOURCE_GENERATOR "TXZ")
set(CPACK_SOURCE_IGNORE_FILES "~$;[.]swp$;/[.]bare/;/[.]git/;/[.]git;/[.]clangd/;/[.]cache/;.gitignore;/build*;/obj*;tags;cscope.*;compile_commands.json;.*\.patch")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")

### NSIS INSTALLER
if (WIN32)
    set(CPACK_GENERATOR "ZIP")

    ### nsis generator
    find_package(NSIS)
    if (NSIS_MAKE)
        set(CPACK_GENERATOR "${CPACK_GENERATOR};NSIS")
        set(CPACK_NSIS_DISPLAY_NAME "The SSH Library")
        set(CPACK_NSIS_COMPRESSOR "/SOLID zlib")
        set(CPACK_NSIS_MENU_LINKS "https://www.libssh.org/" "libssh homepage")
    endif (NSIS_MAKE)
endif (WIN32)

set(CPACK_PACKAGE_INSTALL_DIRECTORY "libssh")

set(CPACK_PACKAGE_FILE_NAME ${APPLICATION_NAME}-${CPACK_PACKAGE_VERSION})

set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "C/C++ Headers")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION
  "Libraries used to build programs which use libssh")
set(CPACK_COMPONENT_HEADERS_DESCRIPTION
  "C/C++ header files for use with libssh")
set(CPACK_COMPONENT_HEADERS_DEPENDS libraries)
set(CPACK_COMPONENT_LIBRARIES_GROUP "Development")
set(CPACK_COMPONENT_HEADERS_GROUP "Development")

include(CPack)
