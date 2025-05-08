cmake_minimum_required(VERSION 3.24)
project(
  COFFLoader
  VERSION 20250508
  DESCRIPTION
    "Quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it."
  HOMEPAGE_URL "https://github.com/MEhrn00/COFFLoader.git"
  LANGUAGES C
)

option(COFFLOADER_BUILD_CLI "Build the COFFLoader CLI binary." OFF)

if(NOT PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  file(GENERATE OUTPUT .gitignore CONTENT "# cmake generated .gitignore\n*\n")
endif()

if(DEFINED COFFLOADER_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ${COFFLOADER_SHARED_LIBS})
endif()


add_library(COFFLoader)
add_library(COFFLoader::COFFLoader ALIAS COFFLoader)

if(${COFFLOADER_BUILD_CLI})
  add_executable(COFFLoader-cli)
endif()

include(GNUInstallDirs)

add_subdirectory(COFFLoader)

install(EXPORT COFFLoaderTargets
  FILE COFFLoaderTargets.cmake
  NAMESPACE COFFLoader::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/COFFLoader
)

install(
  FILES LICENSE.txt
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/COFFLoader
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/COFFLoaderConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/COFFLoaderConfig.cmake
  INSTALL_DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/COFFLoader
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/COFFLoaderConfigVersion.cmake"
  VERSION ${CMAKE_PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/COFFLoaderConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/COFFLoaderConfigVersion.cmake
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/COFFLoader
)
