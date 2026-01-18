cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

# common source files
set(COMMON_SOURCES 
    w1debugger.cpp 
    error.cpp
)

# platform-specific sources
set(PLATFORM_SOURCES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND PLATFORM_SOURCES
        platform/darwin/darwin_session.cpp
        platform/darwin/entitlement_check.cpp
        platform/darwin/process_control.cpp
        platform/darwin/thread_context.cpp
        platform/darwin/memory_ops.cpp
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND PLATFORM_SOURCES
        platform/linux/linux_debugger.cpp
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND PLATFORM_SOURCES
        platform/windows/windows_debugger.cpp
    )
endif()

add_library(w1debugger STATIC ${COMMON_SOURCES} ${PLATFORM_SOURCES})

target_include_directories(w1debugger
    PUBLIC 
        $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# platform-specific libraries
if(APPLE)
    find_library(CORE_FOUNDATION CoreFoundation)
    find_library(SECURITY Security)
    target_link_libraries(w1debugger PRIVATE ${CORE_FOUNDATION} ${SECURITY})
elseif(WIN32)
    target_link_libraries(w1debugger PRIVATE psapi kernel32 advapi32)
elseif(UNIX)
    target_link_libraries(w1debugger PRIVATE pthread)
endif()

# c++20 for std::expected
set_property(TARGET w1debugger PROPERTY CXX_STANDARD 20)
set_property(TARGET w1debugger PROPERTY CXX_STANDARD_REQUIRED ON)

apply_common_compile_options(w1debugger)
apply_windows_definitions(w1debugger)
set_standard_output_dirs(w1debugger)

install(TARGETS w1debugger
    EXPORT w1debuggerTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
