cmake_minimum_required(VERSION 3.24)
project(
  COFFLoader
  DESCRIPTION
    "Quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it."
  LANGUAGES C)


if(NOT PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  file(GENERATE OUTPUT .gitignore CONTENT "# cmake generated .gitignore\n*\n")
endif()

add_subdirectory(COFFLoader)
