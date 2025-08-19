cmake_minimum_required(VERSION 3.12)
project(test_p1ll_standalone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# external projects would use find_package instead
set(W1TNSS_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

# add redlog: p1ll depends on it
add_subdirectory(${W1TNSS_ROOT}/src/third_party/redlog_cpp redlog_cpp EXCLUDE_FROM_ALL)

# configure c api before adding p1ll
option(BUILD_C_API_TEST "Build C API test executable" ON)
if(BUILD_C_API_TEST)
    set(P1LL_BUILD_CAPI ON CACHE BOOL "Enable C API" FORCE)
endif()

# add p1ll core library
add_subdirectory(${W1TNSS_ROOT}/src/p1ll p1ll_standalone_build)

# create c++ test executable
add_executable(test_p1ll_standalone test_p1ll_standalone.cpp)
target_link_libraries(test_p1ll_standalone PRIVATE p1ll_core)

# create c api test executable if enabled
if(BUILD_C_API_TEST)
    # create c test executable
    add_executable(test_p1ll_capi test_p1ll_capi.c)
    target_link_libraries(test_p1ll_capi PRIVATE p1ll_c)
    
    # ensure c standard
    set_target_properties(test_p1ll_capi PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
    )
    
    message(STATUS "c api test executable enabled")
else()
    message(STATUS "c api test executable disabled")
endif()