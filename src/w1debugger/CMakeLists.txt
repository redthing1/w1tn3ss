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

w1_add_static_library(w1debugger ${COMMON_SOURCES} ${PLATFORM_SOURCES})
add_library(w1::debugger ALIAS w1debugger)

# platform-specific libraries
if(APPLE)
    find_library(CORE_FOUNDATION CoreFoundation)
    find_library(SECURITY Security)
    target_link_libraries(w1debugger PRIVATE ${CORE_FOUNDATION} ${SECURITY})
elseif(WIN32)
    target_link_libraries(w1debugger PRIVATE psapi kernel32 advapi32)
elseif(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(w1debugger PRIVATE Threads::Threads)
endif()

install(TARGETS w1debugger
    EXPORT w1debuggerTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
