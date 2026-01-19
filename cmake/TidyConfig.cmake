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

find_program(CLANG_TIDY_EXECUTABLE
    NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15
    PATHS ${CLANG_TIDY_SEARCH_PATHS}
)

if(CLANG_TIDY_EXECUTABLE)
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
endif()
