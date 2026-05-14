cmake_minimum_required(VERSION 3.10)
project(certwatcher VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)

add_executable(certwatcher certwatcher.c)
target_link_libraries(certwatcher OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(certwatcher ws2_32)
endif()

install(TARGETS certwatcher RUNTIME DESTINATION bin)
