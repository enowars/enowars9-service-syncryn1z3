cmake_minimum_required(VERSION 3.25)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ptp ${SOURCES} ${HEADERS})

target_include_directories(ptp PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(ptp PRIVATE ptp-port ptp-protocol ptp-security ptp-tasks)

add_subdirectory(port)
add_subdirectory(protocol)
add_subdirectory(security)
add_subdirectory(tasks)
