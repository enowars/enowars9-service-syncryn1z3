cmake_minimum_required(VERSION 3.25)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(socket ${SOURCES} ${HEADERS})

target_include_directories(socket PUBLIC ${CMAKE_SOURCE_DIR}/src)
