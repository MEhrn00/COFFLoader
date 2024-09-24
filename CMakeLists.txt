cmake_minimum_required(VERSION 3.18)
project(COFFLoader LANGUAGES C)

add_subdirectory(src)

install(FILES LICENSE.txt DESTINATION "share/licenses/${PROJECT_NAME}")

set(CPACK_PACKAGE_VERSION "2024-09-24.1")
include(CPack)
