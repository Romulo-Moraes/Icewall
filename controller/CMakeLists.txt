cmake_minimum_required(VERSION 3.20)

project(controller)

set (SOURCE
    src/wallctl.c
    src/usage.c
    src/parser.c
    src/helpers.c
)

add_executable(wallctl ${SOURCE})

target_include_directories(wallctl PRIVATE includes)
target_include_directories(wallctl PRIVATE "../shared")
