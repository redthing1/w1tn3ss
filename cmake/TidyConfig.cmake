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

find_program(CLANG_TIDY_EXECUTABLE
    NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15
    PATHS ${CLANG_TIDY_SEARCH_PATHS}
)

if(CLANG_TIDY_EXECUTABLE)
    # enable compile commands database for better analysis
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    
    file(GLOB_RECURSE ALL_TIDY_FILES
        "${WITNESS_SOURCE_DIR}/src/w1tn3ss/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1tn3ss/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/w1debugger/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/w1tool/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1tool/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/tracers/*.cpp" "${WITNESS_SOURCE_DIR}/src/tracers/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/w1common/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1common/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/p1ll/*.cpp" "${WITNESS_SOURCE_DIR}/src/p1ll/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/p1llx/*.cpp" "${WITNESS_SOURCE_DIR}/src/p1llx/*.hpp"
        "${WITNESS_SOURCE_DIR}/src/p01s0n/*.cpp" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.hpp"
        "${WITNESS_SOURCE_DIR}/samples/*.cpp" "${WITNESS_SOURCE_DIR}/samples/*.hpp"
        "${WITNESS_SOURCE_DIR}/tests/*.cpp" "${WITNESS_SOURCE_DIR}/tests/*.hpp"
        "${WITNESS_SOURCE_DIR}/test/*.cpp" "${WITNESS_SOURCE_DIR}/test/*.hpp"
    )
    
    list(FILTER ALL_TIDY_FILES EXCLUDE REGEX ".*/build-.*/.*")
    list(FILTER ALL_TIDY_FILES EXCLUDE REGEX ".*/CMakeFiles/.*")
    
    # use compile commands database if available, fallback to manual includes
    if(EXISTS "${CMAKE_BINARY_DIR}/compile_commands.json")
        add_custom_target(w1-tidy
            COMMAND ${CLANG_TIDY_EXECUTABLE} --fix --format-style=file -p ${CMAKE_BINARY_DIR} ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${WITNESS_SOURCE_DIR}
            VERBATIM
        )
        
        add_custom_target(w1-tidy-check
            COMMAND ${CLANG_TIDY_EXECUTABLE} -p ${CMAKE_BINARY_DIR} ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${WITNESS_SOURCE_DIR}
            VERBATIM
        )
    else()
        add_custom_target(w1-tidy
            COMMAND ${CLANG_TIDY_EXECUTABLE} --fix --format-style=file ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${WITNESS_SOURCE_DIR}
            VERBATIM
        )
        
        add_custom_target(w1-tidy-check
            COMMAND ${CLANG_TIDY_EXECUTABLE} ${ALL_TIDY_FILES}
            WORKING_DIRECTORY ${WITNESS_SOURCE_DIR}
            VERBATIM
        )
    endif()
endif()
