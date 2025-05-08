add_library(COFFLoader
  COFFLoader.c
)

target_compile_features(COFFLoader PRIVATE c_std_11)
target_compile_definitions(COFFLoader
  PRIVATE
    COFF_STANDALONE
    $<$<CONFIG:Debug>:DEBUG>
)

target_include_directories(COFFLoader
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
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


add_executable(COFFLoader-cli
  main.c
)

target_include_directories(COFFLoader-cli
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/.."
)

target_link_libraries(COFFLoader-cli PRIVATE COFFLoader)
