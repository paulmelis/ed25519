cmake_minimum_required(VERSION 3.0)

project(ed25519)

option(WITH_PYTHON "Build python wrapper" ON)

# ED25519_NO_SEED

if(WITH_PYTHON)
    cmake_minimum_required(VERSION 3.0)
    find_package(PythonLibs 3 REQUIRED)
endif()

#IF(USE_SSE)
#    SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -finline-functions -msse -msse2")
#    SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -finline-functions -msse -msse2")
#
#    SET(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -finline-functions -msse -msse2")
#    SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -msse -msse2")
#ENDIF()

add_subdirectory(src)
add_subdirectory(test)
