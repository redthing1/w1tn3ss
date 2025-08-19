# p1ll c api wrapper

set(P1LL_CAPI_SOURCES
    p1ll_c.cpp
)

# p1ll_c static library
add_library(p1ll_c STATIC ${P1LL_CAPI_SOURCES})

# link against p1ll_core
target_link_libraries(p1ll_c PUBLIC p1ll_core)

# include directories
target_include_directories(p1ll_c
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# ensure c++ standard for implementation
set_target_properties(p1ll_c PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    POSITION_INDEPENDENT_CODE ON
)

# export header for installation
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    install(FILES p1ll_c.h DESTINATION include)
    install(TARGETS p1ll_c DESTINATION lib)
endif()

message(STATUS "p1ll c api configured")