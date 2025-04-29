cmake_minimum_required(VERSION 3.10)

file(GLOB_RECURSE SOURCES *.c)
file(GLOB_RECURSE HEADERS *.h)

add_executable(ptp-master ${SOURCES} ${HEADERS})
target_include_directories(ptp-master PUBLIC ${CMAKE_CURRENT_LIST_DIR})
