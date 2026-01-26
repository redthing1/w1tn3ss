cmake_minimum_required(VERSION 3.16)

project(embed_w1rewind LANGUAGES CXX)

set(W1TN3SS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")
get_filename_component(W1TN3SS_ROOT "${W1TN3SS_ROOT}" REALPATH)

set(WITNESS_BUILD_ALL OFF CACHE BOOL "Build all w1tn3ss components" FORCE)
set(WITNESS_BUILD_W1REWIND ON CACHE BOOL "Build w1rewind component" FORCE)

add_subdirectory("${W1TN3SS_ROOT}" w1tn3ss_build)

add_executable(embed_w1rewind main.cpp)
set_property(TARGET embed_w1rewind PROPERTY CXX_STANDARD 20)
set_property(TARGET embed_w1rewind PROPERTY CXX_STANDARD_REQUIRED ON)

target_link_libraries(embed_w1rewind PRIVATE w1::rewind::replay)
