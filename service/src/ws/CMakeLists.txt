cmake_minimum_required(VERSION 3.25)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBWEBSOCKETS REQUIRED libwebsockets)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ws ${SOURCES} ${HEADERS})

target_include_directories(ws PUBLIC ${CMAKE_SOURCE_DIR}/src)

target_include_directories(ws PRIVATE ${LIBWEBSOCKETS_INCLUDE_DIRS})
target_link_libraries(ws ${LIBWEBSOCKETS_LIBRARIES})
