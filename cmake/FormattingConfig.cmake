find_program(CLANG_FORMAT_EXECUTABLE
    NAMES clang-format clang-format-18 clang-format-17 clang-format-16 clang-format-15
)

if(CLANG_FORMAT_EXECUTABLE)
    file(GLOB_RECURSE ALL_FORMAT_FILES
        "${WITNESS_SOURCE_DIR}/src/w1tn3ss/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1tn3ss/*.h" "${WITNESS_SOURCE_DIR}/src/w1tn3ss/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1tn3ss/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.h" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1debugger/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.h" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1tool/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1tool/*.h" "${WITNESS_SOURCE_DIR}/src/w1tool/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1tool/*.c"
        "${WITNESS_SOURCE_DIR}/src/tracers/*.cpp" "${WITNESS_SOURCE_DIR}/src/tracers/*.h" "${WITNESS_SOURCE_DIR}/src/tracers/*.hpp" "${WITNESS_SOURCE_DIR}/src/tracers/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1common/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1common/*.h" "${WITNESS_SOURCE_DIR}/src/w1common/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1common/*.c"
        "${WITNESS_SOURCE_DIR}/src/p1ll/*.cpp" "${WITNESS_SOURCE_DIR}/src/p1ll/*.h" "${WITNESS_SOURCE_DIR}/src/p1ll/*.hpp" "${WITNESS_SOURCE_DIR}/src/p1ll/*.c"
        "${WITNESS_SOURCE_DIR}/src/p1llx/*.cpp" "${WITNESS_SOURCE_DIR}/src/p1llx/*.h" "${WITNESS_SOURCE_DIR}/src/p1llx/*.hpp" "${WITNESS_SOURCE_DIR}/src/p1llx/*.c"
        "${WITNESS_SOURCE_DIR}/src/p01s0n/*.cpp" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.h" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.hpp" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.c"
        "${WITNESS_SOURCE_DIR}/tests/*.cpp" "${WITNESS_SOURCE_DIR}/tests/*.h" "${WITNESS_SOURCE_DIR}/tests/*.hpp" "${WITNESS_SOURCE_DIR}/tests/*.c"
    )
    
    list(FILTER ALL_FORMAT_FILES EXCLUDE REGEX ".*/build-.*/.*")
    list(FILTER ALL_FORMAT_FILES EXCLUDE REGEX ".*/CMakeFiles/.*")
    
    add_custom_target(w1-format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i -style=file ${ALL_FORMAT_FILES}
        WORKING_DIRECTORY ${WITNESS_SOURCE_DIR}
        VERBATIM
    )
    
    add_custom_target(w1-format-check
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror -style=file ${ALL_FORMAT_FILES}
        WORKING_DIRECTORY ${WITNESS_SOURCE_DIR}
        VERBATIM
    )
endif()