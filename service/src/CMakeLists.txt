cmake_minimum_required(VERSION 3.25)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(ptp-master ${SOURCES} ${HEADERS})

target_include_directories(ptp-master PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(ptp-master PRIVATE ptp socket)

add_subdirectory(ptp)
add_subdirectory(socket)

