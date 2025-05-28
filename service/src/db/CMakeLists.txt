cmake_minimum_required(VERSION 3.25)

find_package(SQLite3)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(db ${SOURCES} ${HEADERS})

target_link_libraries(db PRIVATE SQLite::SQLite3)
