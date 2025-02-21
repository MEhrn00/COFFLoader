cmake_minimum_required(VERSION 3.18)
project(
  COFFLoader
  DESCRIPTION
    "Quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it."
  LANGUAGES C)

if(NOT PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  file(GENERATE OUTPUT .gitignore CONTENT "# cmake generated .gitignore\n*\n")
endif()

add_executable(COFFLoader
  COFFLoader.c
  beacon_compatibility.c
)

target_compile_features(COFFLoader PRIVATE c_std_11)
target_compile_definitions(COFFLoader
  PRIVATE
    COFF_STANDALONE
    $<$<CONFIG:Debug>:DEBUG>
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
