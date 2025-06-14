set(LIBRARY_NAME w1nj3ct)

# platform-specific source files
set(COMMON_SOURCES
    w1nj3ct.cpp
    error.cpp
)

set(PLATFORM_SOURCES "")

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # include darwin injection backend sources
    list(APPEND PLATFORM_SOURCES
        platform/darwin/darwin_injector.cpp
        # darwin injection backend (copied from reference implementation)
        backend/darwin/injector.c
        backend/darwin/mach.c
        backend/darwin/ptrace.c
        backend/darwin/remote_call.c
        backend/darwin/util.c
        backend/darwin/exc_handler.c
        backend/darwin/mach_excServer.c
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # for now, use same backend as darwin (kubo/injector supports both)
    list(APPEND PLATFORM_SOURCES
        platform/linux/linux_injector.cpp
        # reuse darwin backend for linux (kubo/injector supports both)
        backend/darwin/injector.c
        backend/darwin/ptrace.c
        backend/darwin/remote_call.c
        backend/darwin/util.c
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND PLATFORM_SOURCES
        platform/windows/windows_injector.cpp
        platform/windows/error_windows.cpp
        # windows injection backend (copied from reference implementation)
        backend/windows/inject_createremotethread.cpp
        backend/windows/inject_setwindowshook.cpp
        backend/windows/inject_rtlcreateuserthread.cpp
        backend/windows/inject_reflective.cpp
        backend/windows/auxiliary.cpp
    )
endif()

set(ALL_SOURCES ${COMMON_SOURCES} ${PLATFORM_SOURCES})

# create library
add_library(${LIBRARY_NAME} STATIC ${ALL_SOURCES})

# include directories
target_include_directories(${LIBRARY_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/backend  # for accessing backend headers
)

# link libraries
target_link_libraries(${LIBRARY_NAME}
    PUBLIC
        common
        redlog::redlog
)

# platform-specific linking
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(${LIBRARY_NAME} PRIVATE
        psapi
        kernel32
        user32
        advapi32
        ntdll
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(${LIBRARY_NAME} PRIVATE
        dl
        pthread
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # no extra libraries needed for macOS
endif()

# compiler flags
target_compile_features(${LIBRARY_NAME} PUBLIC cxx_std_17)

# enable sanitizers for injection library in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
    target_compile_options(${LIBRARY_NAME} PRIVATE ${SANITIZER_FLAGS})
    target_link_options(${LIBRARY_NAME} PRIVATE ${SANITIZER_FLAGS})
endif()

# platform-specific compile definitions
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_compile_definitions(${LIBRARY_NAME} PRIVATE
        _WIN32_WINNT=0x0601  # Windows 7+
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

# install rules
install(TARGETS ${LIBRARY_NAME}
    EXPORT w1nj3ctTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES w1nj3ct.hpp error.hpp
    DESTINATION include/w1nj3ct
)