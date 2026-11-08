cmake_minimum_required(VERSION 3.16)
project(clock_independence_experiment LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(clock_experiment clock_experiment.cpp)
target_link_libraries(clock_experiment PRIVATE OpenSSL::Crypto)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(clock_experiment PRIVATE -Wall -Wextra -Wpedantic)
endif()
