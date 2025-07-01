cmake_minimum_required(VERSION 3.16)

include(${CMAKE_SOURCE_DIR}/cmake/CommonConfig.cmake)

# platform-specific source files
set(COMMON_SOURCES w1nj3ct.cpp error.cpp)
set(PLATFORM_SOURCES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND PLATFORM_SOURCES
        platform/darwin/darwin_injector.cpp
        backend/darwin/injector.c backend/darwin/mach.c backend/darwin/ptrace.c
        backend/darwin/remote_call.c backend/darwin/util.c backend/darwin/exc_handler.c
        backend/darwin/mach_excServer.c
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND PLATFORM_SOURCES
        platform/linux/linux_injector.cpp
        backend/linux/injector.c backend/linux/elf.c backend/linux/ptrace.c
        backend/linux/remote_call.c backend/linux/util.c backend/linux/shellcode.S
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND PLATFORM_SOURCES
        platform/windows/windows_injector.cpp platform/windows/error_windows.cpp
        backend/windows/inject_createremotethread.cpp backend/windows/inject_setwindowshook.cpp
        backend/windows/inject_rtlcreateuserthread.cpp backend/windows/inject_reflective.cpp
        backend/windows/inject_launch.cpp backend/windows/auxiliary.cpp
    )
endif()

add_library(w1nj3ct STATIC ${COMMON_SOURCES} ${PLATFORM_SOURCES})

target_include_directories(w1nj3ct
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/backend
)

target_link_libraries(w1nj3ct PUBLIC common redlog::redlog)

# platform-specific libraries
if(WIN32)
    target_link_libraries(w1nj3ct PRIVATE psapi kernel32 user32 advapi32 ntdll)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(w1nj3ct PRIVATE dl pthread)
endif()

apply_common_compile_options(w1nj3ct)
apply_windows_definitions(w1nj3ct)
set_standard_output_dirs(w1nj3ct)

install(TARGETS w1nj3ct
    EXPORT w1nj3ctTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES w1nj3ct.hpp error.hpp DESTINATION include/w1nj3ct)