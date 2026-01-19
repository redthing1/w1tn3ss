include_guard()

# detect homebrew llvm on macos
if(APPLE)
    execute_process(
        COMMAND brew --prefix llvm
        OUTPUT_VARIABLE HOMEBREW_LLVM_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(HOMEBREW_LLVM_PREFIX)
        set(CLANG_TIDY_SEARCH_PATHS "${HOMEBREW_LLVM_PREFIX}/bin")
    endif()
endif()

if(NOT DEFINED W1_SOURCE_DIR)
    set(W1_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()

if(NOT DEFINED W1_ENABLE_CLANG_TIDY)
    option(W1_ENABLE_CLANG_TIDY "Enable clang-tidy for w1 targets" ON)
endif()

find_program(CLANG_TIDY_EXECUTABLE
    NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15
    PATHS ${CLANG_TIDY_SEARCH_PATHS}
)

if(CLANG_TIDY_EXECUTABLE)
    if(NOT DEFINED W1_CLANG_TIDY_COMMAND)
        set(W1_CLANG_TIDY_COMMAND "${CLANG_TIDY_EXECUTABLE};--format-style=file")
    endif()

    if(NOT DEFINED W1_CLANG_TIDY_EXCLUDE_DIRS)
        set(_w1_default_tidy_excludes "${W1_SOURCE_DIR}/src/third_party")
        if(EXISTS "${_w1_default_tidy_excludes}")
            set(W1_CLANG_TIDY_EXCLUDE_DIRS "${_w1_default_tidy_excludes}")
        else()
            set(W1_CLANG_TIDY_EXCLUDE_DIRS "")
        endif()
    endif()

    if(NOT COMMAND w1_apply_clang_tidy)
        function(w1_apply_clang_tidy TARGET_NAME)
            if(NOT W1_ENABLE_CLANG_TIDY)
                return()
            endif()

            if(NOT W1_CLANG_TIDY_COMMAND)
                return()
            endif()

            get_target_property(_w1_aliased ${TARGET_NAME} ALIASED_TARGET)
            if(_w1_aliased)
                return()
            endif()

            get_target_property(_w1_imported ${TARGET_NAME} IMPORTED)
            if(_w1_imported)
                return()
            endif()

            get_target_property(_w1_target_type ${TARGET_NAME} TYPE)
            if(_w1_target_type STREQUAL "INTERFACE_LIBRARY" OR _w1_target_type STREQUAL "UTILITY")
                return()
            endif()

            get_target_property(_w1_skip_tidy ${TARGET_NAME} W1_CLANG_TIDY_SKIP)
            if(_w1_skip_tidy)
                return()
            endif()

            get_target_property(_w1_target_source_dir ${TARGET_NAME} SOURCE_DIR)
            if(_w1_target_source_dir AND W1_CLANG_TIDY_EXCLUDE_DIRS)
                file(TO_CMAKE_PATH "${_w1_target_source_dir}" _w1_target_source_dir_norm)
                foreach(_w1_exclude_dir IN LISTS W1_CLANG_TIDY_EXCLUDE_DIRS)
                    if(NOT _w1_exclude_dir)
                        continue()
                    endif()
                    file(TO_CMAKE_PATH "${_w1_exclude_dir}" _w1_exclude_dir_norm)
                    set(_w1_exclude_dir_norm "${_w1_exclude_dir_norm}/")
                    set(_w1_target_source_dir_check "${_w1_target_source_dir_norm}/")
                    string(FIND "${_w1_target_source_dir_check}" "${_w1_exclude_dir_norm}" _w1_exclude_idx)
                    if(_w1_exclude_idx EQUAL 0)
                        return()
                    endif()
                endforeach()
            endif()

            set_target_properties(${TARGET_NAME} PROPERTIES
                C_CLANG_TIDY "${W1_CLANG_TIDY_COMMAND}"
                CXX_CLANG_TIDY "${W1_CLANG_TIDY_COMMAND}"
            )
        endfunction()
    endif()

    # enable compile commands database for better analysis
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    
    file(GLOB_RECURSE ALL_TIDY_FILES
        "${W1_SOURCE_DIR}/src/w1base/*.cpp" "${W1_SOURCE_DIR}/src/w1base/*.hpp"
        "${W1_SOURCE_DIR}/src/w1formats/*.cpp" "${W1_SOURCE_DIR}/src/w1formats/*.hpp"
        "${W1_SOURCE_DIR}/src/w1runtime/*.cpp" "${W1_SOURCE_DIR}/src/w1runtime/*.hpp"
        "${W1_SOURCE_DIR}/src/w1instrument/*.cpp" "${W1_SOURCE_DIR}/src/w1instrument/*.hpp"
        "${W1_SOURCE_DIR}/src/w1analysis/*.cpp" "${W1_SOURCE_DIR}/src/w1analysis/*.hpp"
        "${W1_SOURCE_DIR}/src/w1import/*.cpp" "${W1_SOURCE_DIR}/src/w1import/*.hpp"
        "${W1_SOURCE_DIR}/src/w1dump/*.cpp" "${W1_SOURCE_DIR}/src/w1dump/*.hpp"
        "${W1_SOURCE_DIR}/src/w1gadget/*.cpp" "${W1_SOURCE_DIR}/src/w1gadget/*.hpp"
        "${W1_SOURCE_DIR}/src/w1rewind/*.cpp" "${W1_SOURCE_DIR}/src/w1rewind/*.hpp"
        "${W1_SOURCE_DIR}/src/w1nj3ct/*.cpp" "${W1_SOURCE_DIR}/src/w1nj3ct/*.hpp"
        "${W1_SOURCE_DIR}/src/w1debugger/*.cpp" "${W1_SOURCE_DIR}/src/w1debugger/*.hpp"
        "${W1_SOURCE_DIR}/src/w1tool/*.cpp" "${W1_SOURCE_DIR}/src/w1tool/*.hpp"
        "${W1_SOURCE_DIR}/src/w1replay/*.cpp" "${W1_SOURCE_DIR}/src/w1replay/*.hpp"
        "${W1_SOURCE_DIR}/src/tracers/*.cpp" "${W1_SOURCE_DIR}/src/tracers/*.hpp"
        "${W1_SOURCE_DIR}/src/p1ll/*.cpp" "${W1_SOURCE_DIR}/src/p1ll/*.hpp"
        "${W1_SOURCE_DIR}/src/p1llx/*.cpp" "${W1_SOURCE_DIR}/src/p1llx/*.hpp"
        "${W1_SOURCE_DIR}/src/p01s0n/*.cpp" "${W1_SOURCE_DIR}/src/p01s0n/*.hpp"
        "${W1_SOURCE_DIR}/samples/*.cpp" "${W1_SOURCE_DIR}/samples/*.hpp"
        "${W1_SOURCE_DIR}/tests/*.cpp" "${W1_SOURCE_DIR}/tests/*.hpp"
        "${W1_SOURCE_DIR}/test/*.cpp" "${W1_SOURCE_DIR}/test/*.hpp"
    )
    
    list(FILTER ALL_TIDY_FILES EXCLUDE REGEX ".*/build-.*/.*")
    list(FILTER ALL_TIDY_FILES EXCLUDE REGEX ".*/CMakeFiles/.*")
    
    # use compile commands database if available, fallback to manual includes
    if(EXISTS "${CMAKE_BINARY_DIR}/compile_commands.json")
        add_custom_target(w1-tidy
            COMMAND ${CLANG_TIDY_EXECUTABLE} --fix --format-style=file -p ${CMAKE_BINARY_DIR} ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${W1_SOURCE_DIR}
            VERBATIM
        )
        
        add_custom_target(w1-tidy-check
            COMMAND ${CLANG_TIDY_EXECUTABLE} -p ${CMAKE_BINARY_DIR} ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${W1_SOURCE_DIR}
            VERBATIM
        )
    else()
        add_custom_target(w1-tidy
            COMMAND ${CLANG_TIDY_EXECUTABLE} --fix --format-style=file ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${W1_SOURCE_DIR}
            VERBATIM
        )
        
        add_custom_target(w1-tidy-check
            COMMAND ${CLANG_TIDY_EXECUTABLE} ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${W1_SOURCE_DIR}
            VERBATIM
        )
    endif()

    get_property(_w1_all_targets GLOBAL PROPERTY TARGETS)
    foreach(_w1_target IN LISTS _w1_all_targets)
        w1_apply_clang_tidy(${_w1_target})
    endforeach()
endif()
