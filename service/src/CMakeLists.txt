cmake_minimum_required(VERSION 3.25)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(syncryn1z3 ${SOURCES} ${HEADERS})

target_include_directories(syncryn1z3 PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(syncryn1z3 PRIVATE ptp socket ws)

target_include_directories(syncryn1z3 PUBLIC ${LIBUV_INCLUDE_DIRS})
target_link_libraries(syncryn1z3 PRIVATE ${LIBUV_LIBRARIES})

add_subdirectory(ptp)
add_subdirectory(socket)
add_subdirectory(ws)

