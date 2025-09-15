cmake_minimum_required(VERSION 3.16)

include(${WITNESS_SOURCE_DIR}/cmake/CommonConfig.cmake)

# minimal core for the new api
set(SOURCES
    w1debugger.cpp
    platform/stub_session.cpp
)

add_library(w1debugger STATIC ${SOURCES})

target_include_directories(w1debugger
    PUBLIC 
        $<BUILD_INTERFACE:${WITNESS_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${WITNESS_SOURCE_DIR}/src
)

target_link_libraries(w1debugger PUBLIC common redlog::redlog)

# c++23 for std::expected
set_property(TARGET w1debugger PROPERTY CXX_STANDARD 23)
set_property(TARGET w1debugger PROPERTY CXX_STANDARD_REQUIRED ON)

apply_common_compile_options(w1debugger)
apply_windows_definitions(w1debugger)
set_standard_output_dirs(w1debugger)

install(TARGETS w1debugger
    EXPORT w1debuggerTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES w1debugger.hpp
    DESTINATION include/w1debugger)
