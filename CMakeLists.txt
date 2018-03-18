cmake_minimum_required(VERSION 3.0)

project(ed25519)

option(WITH_PYTHON "Build python wrapper" ON)

# ED25519_NO_SEED

if(WITH_PYTHON)
    cmake_minimum_required(VERSION 3.0)
    find_package(PythonLibs 3 REQUIRED)
endif()

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native")
SET(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -march=native")

add_subdirectory(src)
add_subdirectory(test)
