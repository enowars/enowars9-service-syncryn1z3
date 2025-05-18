cmake_minimum_required(VERSION 3.25)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(syncryn1z3 ${SOURCES} ${HEADERS})

target_include_directories(syncryn1z3 PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(syncryn1z3 PRIVATE ptp socket)

add_subdirectory(ptp)
add_subdirectory(socket)

