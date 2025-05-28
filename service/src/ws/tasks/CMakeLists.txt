cmake_minimum_required(VERSION 3.25)

find_package(cJSON REQUIRED)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ws-tasks ${SOURCES} ${HEADERS})

target_include_directories(ws-tasks PRIVATE ${CJSON_INCLUDE_DIRS})
target_link_libraries(ws-tasks PRIVATE ${CJSON_LIBRARIES} db)
