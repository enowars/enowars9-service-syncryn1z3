cmake_minimum_required(VERSION 3.25)

find_package(OpenSSL)


file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ws-tasks ${SOURCES} ${HEADERS})

target_link_libraries(ws-tasks PRIVATE OpenSSL::Crypto db json)
