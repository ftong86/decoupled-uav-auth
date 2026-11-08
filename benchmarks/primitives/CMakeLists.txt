cmake_minimum_required(VERSION 3.16)
project(crypto_benchmark_v4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# Stanford PBC (historical Type-A baseline retained for traceability)
find_path(PBC_INCLUDE_DIR
    NAMES pbc.h
    PATHS /usr/local/include /usr/include
    PATH_SUFFIXES pbc
)

find_library(PBC_LIBRARY
    NAMES pbc
    PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu
)

find_library(GMP_LIBRARY
    NAMES gmp
    PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu
)

if(NOT PBC_INCLUDE_DIR)
    message(FATAL_ERROR "PBC header pbc.h not found. Install Stanford PBC and expose its include path.")
endif()

if(NOT PBC_LIBRARY)
    message(FATAL_ERROR "libpbc not found. Install Stanford PBC and expose its library path.")
endif()

if(NOT GMP_LIBRARY)
    message(FATAL_ERROR "libgmp not found. Install GMP development libraries.")
endif()

# Herumi mcl for BLS12-381.
# Recommended workflow:
#   export MCL_ROOT="$HOME/opt/mcl"
# after cloning/building https://github.com/herumi/mcl there.
set(MCL_ROOT "" CACHE PATH "Root of a built herumi/mcl source tree")

set(_MCL_HINTS
    ${MCL_ROOT}
    $ENV{MCL_ROOT}
    /usr/local
    /usr
)

find_path(MCL_INCLUDE_DIR
    NAMES mcl/bn_c384_256.h
    HINTS ${_MCL_HINTS}
    PATH_SUFFIXES include
)

find_library(MCL_LIBRARY
    NAMES mcl
    HINTS ${_MCL_HINTS}
    PATH_SUFFIXES lib build/lib
)

if(NOT MCL_INCLUDE_DIR)
    message(FATAL_ERROR
        "mcl header mcl/bn_c384_256.h not found. "
        "Build herumi/mcl and set MCL_ROOT, e.g. export MCL_ROOT=$HOME/opt/mcl")
endif()

if(NOT MCL_LIBRARY)
    message(FATAL_ERROR
        "libmcl not found. Build herumi/mcl and set MCL_ROOT, "
        "e.g. export MCL_ROOT=$HOME/opt/mcl")
endif()

message(STATUS "PBC include: ${PBC_INCLUDE_DIR}")
message(STATUS "PBC library: ${PBC_LIBRARY}")
message(STATUS "GMP library: ${GMP_LIBRARY}")
message(STATUS "mcl include: ${MCL_INCLUDE_DIR}")
message(STATUS "mcl library: ${MCL_LIBRARY}")

add_executable(crypto_bench crypto_bench.cpp)

target_compile_options(crypto_bench PRIVATE
    -O3
    -DNDEBUG
    -Wno-deprecated-declarations
)

target_include_directories(crypto_bench PRIVATE
    ${PBC_INCLUDE_DIR}
    ${MCL_INCLUDE_DIR}
)

target_link_libraries(crypto_bench PRIVATE
    OpenSSL::Crypto
    ${PBC_LIBRARY}
    ${GMP_LIBRARY}
    ${MCL_LIBRARY}
)
