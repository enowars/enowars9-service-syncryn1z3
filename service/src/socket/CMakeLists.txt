cmake_minimum_required(VERSION 3.25)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(socket ${SOURCES} ${HEADERS})

target_include_directories(socket PUBLIC ${CMAKE_SOURCE_DIR}/src)

target_include_directories(socket PUBLIC ${LIBUV_INCLUDE_DIRS})
target_link_libraries(socket PRIVATE ${LIBUV_LIBRARIES})
