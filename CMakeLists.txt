cmake_minimum_required(VERSION 3.18)
project(
  COFFLoader
  DESCRIPTION
    "Quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it."
  LANGUAGES C)

add_subdirectory(src)

install(FILES LICENSE.txt DESTINATION "share/licenses/${PROJECT_NAME}")

set(CPACK_PACKAGE_VERSION "2024-09-24.1")
include(CPack)
