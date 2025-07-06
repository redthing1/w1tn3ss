# liefconfig.cmake - lief configuration module
# provides functions for setting up lief dependencies

# global lief configuration
option(WITNESS_LIEF "enable lief binary analysis support" OFF)

# validate lief submodule availability
function(validate_lief_submodule)
    set(LIEF_DIR "${CMAKE_SOURCE_DIR}/src/third_party/lief")
    if(NOT EXISTS "${LIEF_DIR}/CMakeLists.txt")
        message(FATAL_ERROR "lief submodule not found at ${LIEF_DIR}. run: git submodule update --init --recursive")
    endif()
    
    set(LIEF_DIR ${LIEF_DIR} PARENT_SCOPE)
endfunction()

# configure a target with lief dependencies
function(configure_target_with_lief target_name)
    if(NOT WITNESS_LIEF)
        return()
    endif()
    
    if(TARGET ${target_name})
        target_link_libraries(${target_name} PRIVATE LIEF::LIEF)
        target_compile_definitions(${target_name} PRIVATE WITNESS_LIEF_ENABLED=1)
    endif()
endfunction()

# setup lief environment
function(setup_lief_environment)
    if(NOT WITNESS_LIEF)
        return()
    endif()
    
    validate_lief_submodule()
    
    # configure lief build options
    set(LIEF_EXAMPLES OFF CACHE BOOL "disable lief examples")
    set(LIEF_TESTS OFF CACHE BOOL "disable lief tests")
    set(LIEF_PYTHON_API OFF CACHE BOOL "disable lief python api")
    set(LIEF_C_API OFF CACHE BOOL "disable lief c api")
    set(LIEF_RUST_API OFF CACHE BOOL "disable lief rust api")
    set(LIEF_LOGGING OFF CACHE BOOL "disable lief logging")
    set(LIEF_ENABLE_JSON OFF CACHE BOOL "disable lief json support")
    
    # export variables for parent scope
    set(LIEF_DIR ${LIEF_DIR} PARENT_SCOPE)
endfunction()