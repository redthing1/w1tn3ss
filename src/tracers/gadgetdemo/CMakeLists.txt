# gadgetdemo tracer - demonstrates gadget execution from QBDI callbacks

# build the preload library
set(GADGETDEMO_SOURCES preload.cpp)

add_library(gadgetdemo_qbdipreload SHARED ${GADGETDEMO_SOURCES})

target_include_directories(gadgetdemo_qbdipreload PRIVATE
    ${CMAKE_SOURCE_DIR}/src/third_party/qbdi/tools/QBDIPreload/include
)

target_link_libraries(gadgetdemo_qbdipreload PRIVATE 
    w1tn3ss  # for gadget_executor
    QBDI_static
    QBDIPreload  # required for preload functionality
    redlog::redlog
)

# apply common compile options
apply_common_compile_options(gadgetdemo_qbdipreload)

# set output directory and remove lib prefix
set_target_properties(gadgetdemo_qbdipreload PROPERTIES
    PREFIX ""  # remove lib prefix
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# install target
install(TARGETS gadgetdemo_qbdipreload
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION lib
)