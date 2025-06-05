cmake_minimum_required(VERSION 3.25)

find_package(OpenSSL)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(ptp-security ${SOURCES} ${HEADERS})

target_link_libraries(ptp-security PRIVATE OpenSSL::Crypto db)
