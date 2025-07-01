# common configuration for all targets
include_guard()

# standard settings
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# default to release build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# critical windows safeseh hack for qbdi assembly compatibility
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 4 AND MSVC)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /SAFESEH:NO")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /SAFESEH:NO")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")
endif()

# common compiler flags
function(apply_common_compile_options target)
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -O2>
        $<$<CXX_COMPILER_ID:MSVC>:/EHsc>
    )
endfunction()

# windows platform definitions
function(apply_windows_definitions target)
    if(WIN32)
        target_compile_definitions(${target} PRIVATE
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            _CRT_SECURE_NO_WARNINGS
        )
    endif()
endfunction()

# platform-specific linking
function(apply_platform_linking target)
    if(WIN32)
        target_link_libraries(${target} PRIVATE psapi kernel32 user32)
    elseif(UNIX AND NOT APPLE)
        target_link_libraries(${target} PRIVATE dl)
    endif()
endfunction()

# standard output directories
function(set_standard_output_dirs target)
    set_target_properties(${target} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
endfunction()