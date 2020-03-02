cmake_minimum_required(VERSION 3.15)
project(ACBE C)

set(CMAKE_C_STANDARD 11)
include_directories("/usr/local/include")
link_directories("/usr/local/lib")
add_executable(ACBE main.c acbe.c acbe.h hash.c hash.h fix.h)
target_link_libraries(ACBE pbc gmp sodium)
