w1_dep_redlog()

# platform-specific source files
set(COMMON_SOURCES w1nj3ct.cpp error.cpp)
set(PLATFORM_SOURCES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND PLATFORM_SOURCES
        platform/darwin/darwin_injector.cpp
        platform/darwin/impl/injector.c platform/darwin/impl/mach.c platform/darwin/impl/ptrace.c
        platform/darwin/impl/remote_call.c platform/darwin/impl/util.c platform/darwin/impl/exc_handler.c
        platform/darwin/impl/mach_excServer.c
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND PLATFORM_SOURCES
        platform/linux/linux_injector.cpp
        platform/linux/impl/injector.c platform/linux/impl/elf.c platform/linux/impl/ptrace.c
        platform/linux/impl/remote_call.c platform/linux/impl/util.c platform/linux/impl/shellcode.S
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND PLATFORM_SOURCES
        platform/windows/windows_injector.cpp platform/windows/error_windows.cpp
        platform/windows/impl/inject_createremotethread.cpp platform/windows/impl/inject_setwindowshook.cpp
        platform/windows/impl/inject_rtlcreateuserthread.cpp platform/windows/impl/inject_reflective.cpp
        platform/windows/impl/inject_launch.cpp platform/windows/impl/auxiliary.cpp
    )
endif()

w1_add_static_library(w1nj3ct ${COMMON_SOURCES} ${PLATFORM_SOURCES})
add_library(w1::nj3ct ALIAS w1nj3ct)

target_link_libraries(w1nj3ct PUBLIC redlog::redlog)

# platform-specific libraries
if(WIN32)
    target_link_libraries(w1nj3ct PRIVATE advapi32 ntdll)
elseif(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(w1nj3ct PRIVATE Threads::Threads)
endif()

install(TARGETS w1nj3ct
    EXPORT w1nj3ctTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
