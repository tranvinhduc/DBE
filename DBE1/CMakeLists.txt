cmake_minimum_required(VERSION 3.15)
project(DBE1 C)

set(CMAKE_C_STANDARD 11)
include_directories("/usr/local/include")

link_directories("/usr/local/lib")

add_executable(DBE1 main.c dbe.c)
target_link_libraries(DBE1 pbc gmp)
