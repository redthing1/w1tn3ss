if(NOT DEFINED W1_SOURCE_DIR)
    set(W1_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()

find_program(CLANG_FORMAT_EXECUTABLE
    NAMES clang-format clang-format-18 clang-format-17 clang-format-16 clang-format-15
)

if(CLANG_FORMAT_EXECUTABLE)
    file(GLOB_RECURSE ALL_FORMAT_FILES
        "${W1_SOURCE_DIR}/src/w1base/*.cpp" "${W1_SOURCE_DIR}/src/w1base/*.h" "${W1_SOURCE_DIR}/src/w1base/*.hpp" "${W1_SOURCE_DIR}/src/w1base/*.c"
        "${W1_SOURCE_DIR}/src/w1formats/*.cpp" "${W1_SOURCE_DIR}/src/w1formats/*.h" "${W1_SOURCE_DIR}/src/w1formats/*.hpp" "${W1_SOURCE_DIR}/src/w1formats/*.c"
        "${W1_SOURCE_DIR}/src/w1runtime/*.cpp" "${W1_SOURCE_DIR}/src/w1runtime/*.h" "${W1_SOURCE_DIR}/src/w1runtime/*.hpp" "${W1_SOURCE_DIR}/src/w1runtime/*.c"
        "${W1_SOURCE_DIR}/src/w1instrument/*.cpp" "${W1_SOURCE_DIR}/src/w1instrument/*.h" "${W1_SOURCE_DIR}/src/w1instrument/*.hpp" "${W1_SOURCE_DIR}/src/w1instrument/*.c"
        "${W1_SOURCE_DIR}/src/w1analysis/*.cpp" "${W1_SOURCE_DIR}/src/w1analysis/*.h" "${W1_SOURCE_DIR}/src/w1analysis/*.hpp" "${W1_SOURCE_DIR}/src/w1analysis/*.c"
        "${W1_SOURCE_DIR}/src/w1import/*.cpp" "${W1_SOURCE_DIR}/src/w1import/*.h" "${W1_SOURCE_DIR}/src/w1import/*.hpp" "${W1_SOURCE_DIR}/src/w1import/*.c"
        "${W1_SOURCE_DIR}/src/w1dump/*.cpp" "${W1_SOURCE_DIR}/src/w1dump/*.h" "${W1_SOURCE_DIR}/src/w1dump/*.hpp" "${W1_SOURCE_DIR}/src/w1dump/*.c"
        "${W1_SOURCE_DIR}/src/w1gadget/*.cpp" "${W1_SOURCE_DIR}/src/w1gadget/*.h" "${W1_SOURCE_DIR}/src/w1gadget/*.hpp" "${W1_SOURCE_DIR}/src/w1gadget/*.c"
        "${W1_SOURCE_DIR}/src/w1rewind/*.cpp" "${W1_SOURCE_DIR}/src/w1rewind/*.h" "${W1_SOURCE_DIR}/src/w1rewind/*.hpp" "${W1_SOURCE_DIR}/src/w1rewind/*.c"
        "${W1_SOURCE_DIR}/src/w1nj3ct/*.cpp" "${W1_SOURCE_DIR}/src/w1nj3ct/*.h" "${W1_SOURCE_DIR}/src/w1nj3ct/*.hpp" "${W1_SOURCE_DIR}/src/w1nj3ct/*.c"
        "${W1_SOURCE_DIR}/src/w1debugger/*.cpp" "${W1_SOURCE_DIR}/src/w1debugger/*.h" "${W1_SOURCE_DIR}/src/w1debugger/*.hpp" "${W1_SOURCE_DIR}/src/w1debugger/*.c"
        "${W1_SOURCE_DIR}/src/w1tool/*.cpp" "${W1_SOURCE_DIR}/src/w1tool/*.h" "${W1_SOURCE_DIR}/src/w1tool/*.hpp" "${W1_SOURCE_DIR}/src/w1tool/*.c"
        "${W1_SOURCE_DIR}/src/w1replay/*.cpp" "${W1_SOURCE_DIR}/src/w1replay/*.h" "${W1_SOURCE_DIR}/src/w1replay/*.hpp" "${W1_SOURCE_DIR}/src/w1replay/*.c"
        "${W1_SOURCE_DIR}/src/tracers/*.cpp" "${W1_SOURCE_DIR}/src/tracers/*.h" "${W1_SOURCE_DIR}/src/tracers/*.hpp" "${W1_SOURCE_DIR}/src/tracers/*.c"
        "${W1_SOURCE_DIR}/src/p1ll/*.cpp" "${W1_SOURCE_DIR}/src/p1ll/*.h" "${W1_SOURCE_DIR}/src/p1ll/*.hpp" "${W1_SOURCE_DIR}/src/p1ll/*.c"
        "${W1_SOURCE_DIR}/src/p1llx/*.cpp" "${W1_SOURCE_DIR}/src/p1llx/*.h" "${W1_SOURCE_DIR}/src/p1llx/*.hpp" "${W1_SOURCE_DIR}/src/p1llx/*.c"
        "${W1_SOURCE_DIR}/src/p01s0n/*.cpp" "${W1_SOURCE_DIR}/src/p01s0n/*.h" "${W1_SOURCE_DIR}/src/p01s0n/*.hpp" "${W1_SOURCE_DIR}/src/p01s0n/*.c"
        "${W1_SOURCE_DIR}/samples/*.cpp" "${W1_SOURCE_DIR}/samples/*.h" "${W1_SOURCE_DIR}/samples/*.hpp" "${W1_SOURCE_DIR}/samples/*.c"
        "${W1_SOURCE_DIR}/tests/*.cpp" "${W1_SOURCE_DIR}/tests/*.h" "${W1_SOURCE_DIR}/tests/*.hpp" "${W1_SOURCE_DIR}/tests/*.c"
        "${W1_SOURCE_DIR}/test/*.cpp" "${W1_SOURCE_DIR}/test/*.h" "${W1_SOURCE_DIR}/test/*.hpp" "${W1_SOURCE_DIR}/test/*.c"
    )
    
    list(FILTER ALL_FORMAT_FILES EXCLUDE REGEX ".*/build-.*/.*")
    list(FILTER ALL_FORMAT_FILES EXCLUDE REGEX ".*/CMakeFiles/.*")
    
    add_custom_target(w1-format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i -style=file ${ALL_FORMAT_FILES}
        WORKING_DIRECTORY ${W1_SOURCE_DIR}
        VERBATIM
    )
    
    add_custom_target(w1-format-check
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror -style=file ${ALL_FORMAT_FILES}
        WORKING_DIRECTORY ${W1_SOURCE_DIR}
        VERBATIM
    )
endif()
