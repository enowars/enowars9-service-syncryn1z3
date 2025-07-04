cmake_minimum_required(VERSION 3.25)


add_library(json SHARED json.c strcpy.c strlen.c strncmp.c)
add_executable(json_test json_test.c)

target_link_libraries(json_test json)
