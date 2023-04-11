cmake_minimum_required(VERSION 3.16)
project(Test_task)

set(CMAKE_CXX_STANDARD 17)

add_executable(Test_task Source.cpp)

if (UNIX AND NOT APPLE)
    target_link_libraries(Test_task ${CMAKE_DL_LIBS})
endif()