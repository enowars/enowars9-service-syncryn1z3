cmake_minimum_required(VERSION 3.25)


add_library(json SHARED json.c strcpy.c strlen.c strncmp.c)
add_executable(json_test json_test.c)

target_compile_options(json PRIVATE -O0 -fno-plt)

# Make the reversing harder/easier
# add_compile_definitions(JSON_WITH_ARRAY)

include_directories(${CMAKE_SOURCE_DIR}/../service/lib/include)

target_link_libraries(json_test json)
