cmake_minimum_required(VERSION 3.24)
project(
  COFFLoader
  DESCRIPTION
    "Quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it."
  LANGUAGES C)

option(COFFLOADER_BUILD_CLI "Build the COFFLoader CLI binary." OFF)

if(NOT PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  file(GENERATE OUTPUT .gitignore CONTENT "# cmake generated .gitignore\n*\n")
endif()

if(DEFINED COFFLOADER_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ${COFFLOADER_SHARED_LIBS})
endif()

add_subdirectory(COFFLoader)
