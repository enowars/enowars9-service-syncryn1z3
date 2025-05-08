cmake_minimum_required(VERSION 3.25)

find_package(SQLite3)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ptp-peer ${SOURCES} ${HEADERS})

target_include_directories(ptp-peer PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(ptp-peer PRIVATE SQLite::SQLite3)
