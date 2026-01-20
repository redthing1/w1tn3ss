# p1ll c api wrapper

set(P1LL_CAPI_SOURCES
    p1ll_c.cpp
)

# p1ll_c static library
w1_add_static_library(p1ll_c ${P1LL_CAPI_SOURCES})
add_library(p1ll::capi ALIAS p1ll_c)

# link against p1ll_core
target_link_libraries(p1ll_c PUBLIC p1ll_core)

# include directories
target_include_directories(p1ll_c
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# export header for installation
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    install(TARGETS p1ll_c DESTINATION lib COMPONENT ${W1_INSTALL_COMPONENT})
endif()

message(STATUS "p1ll c api configured")
