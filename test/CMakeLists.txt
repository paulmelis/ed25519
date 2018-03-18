include_directories("${PROJECT_SOURCE_DIR}/src")

add_executable(example "example.c")
target_link_libraries(example ed25519)
