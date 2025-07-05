cmake_minimum_required(VERSION 3.25)


add_library(json SHARED IMPORTED GLOBAL)

set_target_properties(json PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_LIST_DIR}/libjson.so)

target_include_directories(json INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
