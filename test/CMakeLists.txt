include_directories("${PROJECT_SOURCE_DIR}/src")

add_executable(example "test.c")
target_link_libraries(example ed25519)
