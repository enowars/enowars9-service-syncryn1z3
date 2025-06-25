cmake_minimum_required(VERSION 3.25)


add_library(timing SHARED memcmp.c strncmp.c)

target_link_libraries(timing)
