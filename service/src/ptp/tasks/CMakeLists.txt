cmake_minimum_required(VERSION 3.25)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ptp-tasks ${SOURCES} ${HEADERS})

target_link_libraries(ptp-tasks PRIVATE ptp-protocol ptp-security db)
