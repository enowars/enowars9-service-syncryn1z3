cmake_minimum_required(VERSION 3.25)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED libuv)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(syncryn1z3 ${SOURCES} ${HEADERS})

include_directories(${CMAKE_SOURCE_DIR}/src)

target_link_libraries(syncryn1z3 PRIVATE db ptp udp http)

target_include_directories(syncryn1z3 PUBLIC ${LIBUV_INCLUDE_DIRS})
target_link_libraries(syncryn1z3 PRIVATE ${LIBUV_LIBRARIES})

add_subdirectory(db)
add_subdirectory(ptp)
add_subdirectory(udp)
add_subdirectory(http)
