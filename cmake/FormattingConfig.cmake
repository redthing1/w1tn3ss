find_program(CLANG_FORMAT_EXECUTABLE
    NAMES clang-format clang-format-18 clang-format-17 clang-format-16 clang-format-15
)

if(CLANG_FORMAT_EXECUTABLE)
    file(GLOB_RECURSE ALL_FORMAT_FILES
        "${WITNESS_SOURCE_DIR}/src/w1base/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1base/*.h" "${WITNESS_SOURCE_DIR}/src/w1base/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1base/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1formats/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1formats/*.h" "${WITNESS_SOURCE_DIR}/src/w1formats/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1formats/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1runtime/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1runtime/*.h" "${WITNESS_SOURCE_DIR}/src/w1runtime/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1runtime/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1instrument/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1instrument/*.h" "${WITNESS_SOURCE_DIR}/src/w1instrument/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1instrument/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1analysis/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1analysis/*.h" "${WITNESS_SOURCE_DIR}/src/w1analysis/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1analysis/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1import/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1import/*.h" "${WITNESS_SOURCE_DIR}/src/w1import/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1import/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1dump/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1dump/*.h" "${WITNESS_SOURCE_DIR}/src/w1dump/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1dump/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1gadget/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1gadget/*.h" "${WITNESS_SOURCE_DIR}/src/w1gadget/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1gadget/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1rewind/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1rewind/*.h" "${WITNESS_SOURCE_DIR}/src/w1rewind/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1rewind/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.h" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1nj3ct/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1debugger/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.h" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1debugger/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1tool/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1tool/*.h" "${WITNESS_SOURCE_DIR}/src/w1tool/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1tool/*.c"
        "${WITNESS_SOURCE_DIR}/src/w1replay/*.cpp" "${WITNESS_SOURCE_DIR}/src/w1replay/*.h" "${WITNESS_SOURCE_DIR}/src/w1replay/*.hpp" "${WITNESS_SOURCE_DIR}/src/w1replay/*.c"
        "${WITNESS_SOURCE_DIR}/src/tracers/*.cpp" "${WITNESS_SOURCE_DIR}/src/tracers/*.h" "${WITNESS_SOURCE_DIR}/src/tracers/*.hpp" "${WITNESS_SOURCE_DIR}/src/tracers/*.c"
        "${WITNESS_SOURCE_DIR}/src/p1ll/*.cpp" "${WITNESS_SOURCE_DIR}/src/p1ll/*.h" "${WITNESS_SOURCE_DIR}/src/p1ll/*.hpp" "${WITNESS_SOURCE_DIR}/src/p1ll/*.c"
        "${WITNESS_SOURCE_DIR}/src/p1llx/*.cpp" "${WITNESS_SOURCE_DIR}/src/p1llx/*.h" "${WITNESS_SOURCE_DIR}/src/p1llx/*.hpp" "${WITNESS_SOURCE_DIR}/src/p1llx/*.c"
        "${WITNESS_SOURCE_DIR}/src/p01s0n/*.cpp" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.h" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.hpp" "${WITNESS_SOURCE_DIR}/src/p01s0n/*.c"
        "${WITNESS_SOURCE_DIR}/samples/*.cpp" "${WITNESS_SOURCE_DIR}/samples/*.h" "${WITNESS_SOURCE_DIR}/samples/*.hpp" "${WITNESS_SOURCE_DIR}/samples/*.c"
        "${WITNESS_SOURCE_DIR}/tests/*.cpp" "${WITNESS_SOURCE_DIR}/tests/*.h" "${WITNESS_SOURCE_DIR}/tests/*.hpp" "${WITNESS_SOURCE_DIR}/tests/*.c"
        "${WITNESS_SOURCE_DIR}/test/*.cpp" "${WITNESS_SOURCE_DIR}/test/*.h" "${WITNESS_SOURCE_DIR}/test/*.hpp" "${WITNESS_SOURCE_DIR}/test/*.c"
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
