cmake_minimum_required(VERSION 3.1)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/;/usr/local/")

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(SEND_ERROR "In-source builds are not allowed.")
endif ()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 17)

if (CMAKE_BUILD_TYPE MATCHES Debug)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -gdwarf-4 -g3 -g -rdynamic")
  set(GCC_OPTIMIZATION "-O0")
endif ()

set(GCC_COVERAGE_COMPILE_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas -Werror -Wno-error=unused-variable -Wno-error=unused-but-set-variable -Wno-error=pragmas -Wno-error=unused-local-typedefs")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS} ${GCC_OPTIMIZATION}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")

project(tsuki_re LANGUAGES C CXX)

include_directories(include)

add_executable(cxa_demangle
  src/cxa_demangle.cpp
)

add_executable(patch_nso
  src/patch_nso.cpp
)
target_link_libraries(patch_nso
  lz4
  ssl
  crypto
)

add_executable(rewrite_nso
  src/rewrite_nso.cpp
)
target_link_libraries(rewrite_nso
  lz4
  ssl
  crypto
)

add_executable(mkips
  src/mkips.cpp
)

add_executable(gen_ips
  src/gen_ips.cpp
)

add_executable(unmzx
  src/unmzx.cpp
)
