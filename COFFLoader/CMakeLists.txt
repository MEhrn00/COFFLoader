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

