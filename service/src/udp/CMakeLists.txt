cmake_minimum_required(VERSION 3.25)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(udp ${SOURCES} ${HEADERS})

target_include_directories(udp PUBLIC ${LIBUV_INCLUDE_DIRS})
target_link_libraries(udp PRIVATE ${LIBUV_LIBRARIES})
