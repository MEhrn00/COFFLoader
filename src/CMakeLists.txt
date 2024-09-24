set(cc_variant ${CMAKE_C_COMPILER_FRONTEND_VARIANT})
if(${cc_variant} STREQUAL "")
  set(cc_variant ${CMAKE_C_COMPILER_ID})
endif()

add_library(COFFLoader COFFLoader.c beacon_compatibility.c)
target_compile_features(COFFLoader PRIVATE c_std_11)
set_target_properties(
  COFFLoader PROPERTIES PUBLIC_HEADER
                        "${CMAKE_SOURCE_DIR}/include/COFFLoader/COFFLoader.h")

target_include_directories(
  COFFLoader PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
                    $<INSTALL_INTERFACE:include>)

target_compile_options(
  COFFLoader
  PRIVATE $<$<STREQUAL:${cc_variant},GNU>:-Wall>
          $<$<STREQUAL:${cc_variant},Clang>:-Wall>
          $<$<STREQUAL:${cc_variant},MSVC>:/W2>)

install(
  TARGETS COFFLoader
  EXPORT "${CMAKE_PROJECT_NAME}Targets"
  CONFIGURATIONS ${CMAKE_CONFIGURATION_TYPES}
  PUBLIC_HEADER DESTINATION "include/${PROJECT_NAME}")

include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
        DESTINATION "lib/cmake/${PROJECT_NAME}")

install(
  EXPORT "${PROJECT_NAME}Targets"
  DESTINATION "lib/cmake/${PROJECT_NAME}"
  NAMESPACE "${PROJECT_NAME}::")

add_executable(COFFLoader-bin main.c)
set_target_properties(COFFLoader-bin PROPERTIES OUTPUT_NAME "COFFLoader" SUFFIX
                                                                         ".exe")
target_compile_options(
  COFFLoader-bin
  PRIVATE $<$<STREQUAL:${cc_variant},GNU>:-Wall>
          $<$<STREQUAL:${cc_variant},Clang>:-Wall>
          $<$<STREQUAL:${cc_variant},MSVC>:/W2>)

target_link_libraries(COFFLoader-bin PRIVATE COFFLoader)
