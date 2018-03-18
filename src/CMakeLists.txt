set(LIB_SOURCES
  add_scalar.c fe.c ge.c hash.c key_exchange.c keypair.c sc.c seed.c sha512.c sign.c verify.c)

include_directories("${PROJECT_SOURCE_DIR}/src")

# C library, without any Python stuff
add_library(ed25519 ${LIB_SOURCES})

if(WITH_PYTHON)
    # C library + Python interface
    include_directories(${PYTHON_INCLUDE_DIRS})
    add_library(ed25519_python ${LIB_SOURCES} pyapi.c)
    set_target_properties(ed25519_python PROPERTIES POSITION_INDEPENDENT_CODE ON)
    set_target_properties(ed25519_python PROPERTIES COMPILE_DEFINITIONS WITH_PYTHON)
    target_link_libraries(ed25519_python ${PYTHON_LIBRARIES})
    
    # Python module, using the above library
    add_library(wrapper MODULE pyapi.c)
    target_link_libraries(wrapper ${PYTHON_LIBRARIES} ed25519_python)
    set_target_properties(wrapper PROPERTIES PREFIX "")
    set_target_properties(wrapper PROPERTIES OUTPUT_NAME "ed25519")
endif()
