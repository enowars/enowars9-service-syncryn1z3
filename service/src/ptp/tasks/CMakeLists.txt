cmake_minimum_required(VERSION 3.25)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ptp-tasks ${SOURCES} ${HEADERS})

target_include_directories(ptp-tasks PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(ptp-tasks PRIVATE ptp-protocol)
