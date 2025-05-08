target_sources(COFFLoader
  PRIVATE
    COFFLoader.c

  PUBLIC
    FILE_SET public_source_headers
    TYPE HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/..
    FILES
      COFFLoader.h
)

target_compile_features(COFFLoader PRIVATE c_std_11)
target_compile_definitions(COFFLoader
  PRIVATE
    $<$<CONFIG:Debug>:DEBUG>

  PUBLIC
    $<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:COFFLOADER_STATIC_DEFINE>
)

target_compile_options(COFFLoader
  PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang>:
      -Wall
    >
    $<$<C_COMPILER_ID:MSVC>:
      /W2
    >
)

include(GenerateExportHeader)
generate_export_header(COFFLoader
  EXPORT_MACRO_NAME COFFLOADER_API
  INCLUDE_GUARD_NAME COFFLOADER_EXPORT_H
  EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/COFFLoader/export.h
)

target_sources(COFFLoader
  PUBLIC
    FILE_SET public_generated_headers
    TYPE HEADERS
    BASE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/include
    FILES
      ${CMAKE_CURRENT_BINARY_DIR}/include/COFFLoader/export.h
)

install(TARGETS COFFLoader
  EXPORT COFFLoaderTargets
  FILE_SET public_source_headers
  FILE_SET public_generated_headers
)


if(${COFFLOADER_BUILD_CLI})
  target_sources(COFFLoader-cli
    PRIVATE
      main.c
  )

  target_include_directories(COFFLoader-cli
    PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/.."
  )

  target_link_libraries(COFFLoader-cli PRIVATE COFFLoader::COFFLoader)
endif()
