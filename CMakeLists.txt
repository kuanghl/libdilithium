cmake_minimum_required(VERSION 3.5.1)

project(dilithium C)

# debug or release compile c flags
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -Wall -g2 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE     "-Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
                                -Wshadow -Wvla -Wpointer-arith -O3 -fomit-frame-pointer")

# select Dilithium2/3/5
option(nl "set the Dilithium NIST Level(2-4x4,3-6x5,5-8x7)" 2)
if(nl)
    message(STATUS "Config: NIST Level=${nl}")
    add_definitions("-DDILITHIUM_MODE=${nl}") 
endif()

# build
add_subdirectory(src)
add_subdirectory(test)