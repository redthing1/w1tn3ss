cmake_minimum_required(VERSION 3.12)
project(test_p1ll_standalone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# external projects would use find_package instead
set(W1TNSS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

# add redlog: p1ll depends on it
add_subdirectory(${W1TNSS_ROOT}/src/third_party/redlog_cpp redlog_cpp EXCLUDE_FROM_ALL)

# add p1ll core library
add_subdirectory(${W1TNSS_ROOT}/src/p1ll p1ll_standalone_build)

# create test executable
add_executable(test_p1ll_standalone main.cpp)
target_link_libraries(test_p1ll_standalone PRIVATE p1ll_core)