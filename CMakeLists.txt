cmake_minimum_required(VERSION 3.19.0)
project(testbug VERSION 0.1.0 LANGUAGES CXX)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/$<CONFIG>")
set(CMAKE_CXX_STANDARD 17)

add_executable(main main.cpp)

