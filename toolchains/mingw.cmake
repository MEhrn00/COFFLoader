if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_SYSTEM_NAME Windows)
endif()

if(NOT DEFINED CMAKE_SYSTEM_PROCESSOR)
  set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
endif()

if(NOT DEFINED ENV{CC})
  find_program(CMAKE_C_COMPILER "${CMAKE_SYSTEM_PROCESSOR}-w64-mingw32-gcc"
               REQUIRED)
endif()

if(NOT DEFINED ENV{AR})
  find_program(CMAKE_AR "${CMAKE_SYSTEM_PROCESSOR}-w64-mingw32-ar" REQUIRED)
endif()

if(NOT (DEFINED CMAKE_SYSROOT AND NOT CMAKE_SYSROOT STREQUAL ""))
  execute_process(
    COMMAND "${CMAKE_C_COMPILER} -print-sysroot"
    OUTPUT_VARIABLE CMAKE_SYSROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
