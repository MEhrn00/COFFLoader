cmake_minimum_required(VERSION 3.18)
project(COFFLoader LANGUAGES C)

if(NOT DEFINED CMAKE_C_VISIBILITY_PRESET AND
    NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN)
  set(CMAKE_C_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
endif()

set(cc_variant ${CMAKE_C_COMPILER_FRONTEND_VARIANT})
if(${cc_variant} STREQUAL "")
  set(cc_variant ${CMAKE_C_COMPILER_ID})
endif()

add_library(COFFLoader COFFLoader.c beacon_compatibility.c)
target_compile_features(COFFLoader PRIVATE c_std_11)
set_target_properties(
  COFFLoader
  PROPERTIES
    PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/${PROJECT_NAME}/${PROJECT_NAME}.h")

target_include_directories(
  COFFLoader
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>)

target_compile_options(
  COFFLoader
  PRIVATE $<$<STREQUAL:${cc_variant},GNU>:-Wall>
          $<$<STREQUAL:${cc_variant},Clang>:-Wall>
          $<$<STREQUAL:${cc_variant},MSVC>:/W2>)

include(GenerateExportHeader)
generate_export_header(
  COFFLoader
  BASE_NAME ${PROJECT_NAME}
  EXPORT_FILE_NAME "${CMAKE_BINARY_DIR}/include/${PROJECT_NAME}/export.h"
)
target_compile_definitions(
  COFFLoader
  PUBLIC
    "$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:COFFLOADER_STATIC_DEFINE>")

install(
  TARGETS COFFLoader
  EXPORT "${PROJECT_NAME}Targets"
  CONFIGURATIONS ${CMAKE_CONFIGURATION_TYPES}
  PUBLIC_HEADER DESTINATION "include/${PROJECT_NAME}")

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}")

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  DESTINATION "lib/cmake/${PROJECT_NAME}")

install(
  EXPORT "${PROJECT_NAME}Targets"
  DESTINATION "lib/cmake/${PROJECT_NAME}"
  NAMESPACE "${PROJECT_NAME}::")

install(
  FILES "${CMAKE_BINARY_DIR}/include/${PROJECT_NAME}/export.h"
  DESTINATION "include/${PROJECT_NAME}")

add_executable(COFFLoader-bin main.c)
set_target_properties(COFFLoader-bin
  PROPERTIES
    OUTPUT_NAME "COFFLoader"
    SUFFIX ".exe")

target_compile_options(
  COFFLoader-bin
  PRIVATE $<$<STREQUAL:${cc_variant},GNU>:-Wall>
          $<$<STREQUAL:${cc_variant},Clang>:-Wall>
          $<$<STREQUAL:${cc_variant},MSVC>:/W2>)

target_link_libraries(COFFLoader-bin PRIVATE COFFLoader)
