cmake_minimum_required(VERSION 3.25)

project(syncryn1z3)

set(CMAKE_C_STANDARD 23)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -fPIC -fstack-protector-strong")

add_subdirectory(src)
add_subdirectory(lib)
