cmake_minimum_required(VERSION 3.15)
project(DBE2 C)

set(CMAKE_C_STANDARD 99)
include_directories("/usr/local/include")

link_directories("/usr/local/lib")

add_executable(DBE2 main.c dbe2.c)
target_link_libraries(DBE2 pbc gmp)
