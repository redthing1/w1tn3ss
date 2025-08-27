cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

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

add_library(w1nj3ct STATIC ${COMMON_SOURCES} ${PLATFORM_SOURCES})

target_include_directories(w1nj3ct
    PUBLIC $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src> $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
            ${WITNESS_SOURCE_DIR}/src
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