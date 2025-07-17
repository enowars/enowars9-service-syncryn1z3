cmake_minimum_required(VERSION 3.25)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBWEBSOCKETS REQUIRED libwebsockets)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(http ${SOURCES} ${HEADERS})

target_include_directories(http PRIVATE ${LIBWEBSOCKETS_INCLUDE_DIRS})
target_link_libraries(http PRIVATE ${LIBWEBSOCKETS_LIBRARIES} http-tasks)

add_subdirectory(tasks)
