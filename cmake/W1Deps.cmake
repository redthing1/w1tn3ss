# dependency setup for w1tn3ss
include_guard()

include(FetchContent)

if(NOT DEFINED WITNESS_SOURCE_DIR)
    set(WITNESS_SOURCE_DIR "${PROJECT_SOURCE_DIR}")
endif()

if(NOT COMMAND w1_set_cache_default)
    include("${CMAKE_CURRENT_LIST_DIR}/W1Options.cmake")
endif()

function(w1_dep_redlog)
    if(TARGET redlog::redlog)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(redlog CONFIG QUIET)
        if(TARGET redlog::redlog)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/redlog_cpp/CMakeLists.txt")
        message(FATAL_ERROR "redlog_cpp submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/redlog_cpp. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(REDLOG_BUILD_EXAMPLES BOOL OFF "Build redlog examples")
    w1_set_cache_default(REDLOG_BUILD_TESTS BOOL OFF "Build redlog tests")

    FetchContent_Declare(redlog_cpp SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/redlog_cpp")
    FetchContent_MakeAvailable(redlog_cpp)
endfunction()

function(w1_dep_nlohmann_json)
    if(TARGET nlohmann_json::nlohmann_json)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(nlohmann_json CONFIG QUIET)
        if(TARGET nlohmann_json::nlohmann_json)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/nlohmann_json/CMakeLists.txt")
        message(FATAL_ERROR "nlohmann_json submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/nlohmann_json. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(JSON_BuildTests BOOL OFF "Build nlohmann_json tests")

    FetchContent_Declare(nlohmann_json SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/nlohmann_json")
    FetchContent_MakeAvailable(nlohmann_json)
endfunction()

function(w1_dep_gdbstub)
    if(TARGET gdbstub::gdbstub)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(gdbstub_cpp CONFIG QUIET)
        if(TARGET gdbstub::gdbstub)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/gdbstub_cpp/CMakeLists.txt")
        message(FATAL_ERROR "gdbstub_cpp submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/gdbstub_cpp. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(GDBSTUB_BUILD_TESTS BOOL OFF "Build gdbstub_cpp tests")

    FetchContent_Declare(gdbstub_cpp SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/gdbstub_cpp")
    FetchContent_MakeAvailable(gdbstub_cpp)

    if(TARGET gdbstub AND NOT TARGET gdbstub::gdbstub)
        add_library(gdbstub::gdbstub ALIAS gdbstub)
    endif()
endfunction()

function(w1_dep_plthook)
    if(TARGET plthook::plthook)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(plthook CONFIG QUIET)
        if(TARGET plthook::plthook)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/plthook/CMakeLists.txt")
        message(FATAL_ERROR "plthook submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/plthook. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(PLTHOOK_BUILD_TESTS BOOL OFF "Build plthook tests")

    FetchContent_Declare(plthook SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/plthook")
    FetchContent_MakeAvailable(plthook)

    if(TARGET plthook AND NOT TARGET plthook::plthook)
        add_library(plthook::plthook ALIAS plthook)
    endif()
endfunction()

function(w1_dep_funchook)
    if(NOT WIN32)
        return()
    endif()

    if(TARGET funchook::funchook)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(funchook CONFIG QUIET)
        if(TARGET funchook::funchook)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/funchook/CMakeLists.txt")
        message(FATAL_ERROR "funchook submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/funchook. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(FUNCHOOK_BUILD_TESTS BOOL OFF "Build funchook tests")
    w1_set_cache_default(FUNCHOOK_BUILD_SHARED BOOL OFF "Build funchook shared library")
    w1_set_cache_default(FUNCHOOK_BUILD_STATIC BOOL ON "Build funchook static library")

    FetchContent_Declare(funchook SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/funchook")
    FetchContent_MakeAvailable(funchook)

    if(TARGET funchook-static AND NOT TARGET funchook::funchook)
        add_library(funchook::funchook ALIAS funchook-static)
    elseif(TARGET funchook-shared AND NOT TARGET funchook::funchook)
        add_library(funchook::funchook ALIAS funchook-shared)
    endif()
endfunction()

function(w1_dep_qbdi)
    if(TARGET QBDI_static OR TARGET QBDI::QBDI)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(QBDI CONFIG QUIET)
        if(TARGET QBDI_static OR TARGET QBDI::QBDI)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/qbdi/CMakeLists.txt")
        message(FATAL_ERROR "QBDI submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/qbdi. Run: git submodule update --init --recursive")
    endif()

    include("${WITNESS_CMAKE_DIR}/PlatformConfig.cmake")
    detect_qbdi_platform()
    detect_architecture()

    w1_set_cache_default(QBDI_SHARED_LIBRARY BOOL OFF "Build QBDI shared library")
    w1_set_cache_default(QBDI_STATIC_LIBRARY BOOL ON "Build QBDI static library")
    w1_set_cache_default(QBDI_LLVM_PRUNE BOOL ON "Prune nonessential LLVM sources from QBDI checkout")

    if(WITNESS_QBDI_EXTRAS)
        w1_set_cache_default(QBDI_TEST BOOL ON "Build QBDI tests")
        w1_set_cache_default(QBDI_EXAMPLES BOOL ON "Build QBDI examples")
        w1_set_cache_default(QBDI_BENCHMARK BOOL ON "Build QBDI benchmark")
        w1_set_cache_default(QBDI_TOOLS_PYQBDI BOOL ON "Build pyqbdi")
        w1_set_cache_default(QBDI_TOOLS_FRIDAQBDI BOOL ON "Build frida-qbdi")
    else()
        w1_set_cache_default(QBDI_TEST BOOL OFF "Build QBDI tests")
        w1_set_cache_default(QBDI_EXAMPLES BOOL OFF "Build QBDI examples")
        w1_set_cache_default(QBDI_BENCHMARK BOOL OFF "Build QBDI benchmark")
        w1_set_cache_default(QBDI_TOOLS_PYQBDI BOOL OFF "Build pyqbdi")
        w1_set_cache_default(QBDI_TOOLS_FRIDAQBDI BOOL OFF "Build frida-qbdi")
    endif()

    w1_set_cache_default(QBDI_TOOLS_QBDIPRELOAD BOOL ON "Build QBDIPreload")
    w1_set_cache_default(QBDI_LOG_DEBUG BOOL OFF "Enable QBDI debug logging")
    w1_set_cache_default(QBDI_CCACHE BOOL ON "Enable QBDI ccache")
    w1_set_cache_default(QBDI_DISABLE_AVX BOOL OFF "Disable AVX in QBDI")
    w1_set_cache_default(QBDI_ASAN BOOL OFF "Enable QBDI ASAN")
    w1_set_cache_default(QBDI_INCLUDE_DOCS BOOL OFF "Enable QBDI docs")

    FetchContent_Declare(qbdi SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/qbdi")
    FetchContent_MakeAvailable(qbdi)

    get_directory_property(_w1_qbdi_targets DIRECTORY "${WITNESS_SOURCE_DIR}/src/third_party/qbdi" BUILDSYSTEM_TARGETS)
    foreach(_target IN LISTS _w1_qbdi_targets)
        if(TARGET ${_target})
            set_property(TARGET ${_target} PROPERTY CXX_STANDARD 17)
            set_property(TARGET ${_target} PROPERTY CXX_STANDARD_REQUIRED ON)
        endif()
    endforeach()

    if(NOT TARGET QBDI_static)
        message(FATAL_ERROR "QBDI_static target not found. QBDI static library is required.")
    endif()

    if(NOT TARGET QBDI::QBDI)
        add_library(QBDI::QBDI ALIAS QBDI_static)
    endif()
endfunction()

function(w1_dep_lief)
    if(TARGET w1::lief)
        return()
    endif()

    add_library(w1_lief INTERFACE)
    add_library(w1::lief ALIAS w1_lief)

    if(NOT WITNESS_LIEF)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(LIEF CONFIG QUIET)
        if(TARGET LIEF::LIEF)
            target_link_libraries(w1_lief INTERFACE LIEF::LIEF)
            target_compile_definitions(w1_lief INTERFACE WITNESS_LIEF_ENABLED=1)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/lief/CMakeLists.txt")
        message(FATAL_ERROR "LIEF submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/lief. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(LIEF_EXAMPLES BOOL OFF "Disable LIEF examples")
    w1_set_cache_default(LIEF_TESTS BOOL OFF "Disable LIEF tests")
    w1_set_cache_default(LIEF_PYTHON_API BOOL OFF "Disable LIEF Python API")
    w1_set_cache_default(LIEF_C_API BOOL OFF "Disable LIEF C API")
    w1_set_cache_default(LIEF_RUST_API BOOL OFF "Disable LIEF Rust API")
    w1_set_cache_default(LIEF_LOGGING BOOL OFF "Disable LIEF logging")
    w1_set_cache_default(LIEF_ENABLE_JSON BOOL OFF "Disable LIEF JSON")

    FetchContent_Declare(lief SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/lief")
    FetchContent_MakeAvailable(lief)

    get_directory_property(_w1_lief_targets DIRECTORY "${WITNESS_SOURCE_DIR}/src/third_party/lief" BUILDSYSTEM_TARGETS)
    foreach(_target IN LISTS _w1_lief_targets)
        if(TARGET ${_target})
            set_property(TARGET ${_target} PROPERTY CXX_STANDARD 17)
            set_property(TARGET ${_target} PROPERTY CXX_STANDARD_REQUIRED ON)
        endif()
    endforeach()

    if(TARGET LIEF::LIEF)
        target_link_libraries(w1_lief INTERFACE LIEF::LIEF)
        target_compile_definitions(w1_lief INTERFACE WITNESS_LIEF_ENABLED=1)
    endif()
endfunction()

function(w1_dep_asmr)
    if(NOT WITNESS_ASMR)
        return()
    endif()

    if(TARGET w1::asmr_deps)
        return()
    endif()

    include("${WITNESS_CMAKE_DIR}/AsmrConfig.cmake")
    configure_asmr_dependencies()

    if(TARGET capstone::capstone AND TARGET keystone::keystone)
        add_library(w1_asmr_deps INTERFACE)
        add_library(w1::asmr_deps ALIAS w1_asmr_deps)
        target_link_libraries(w1_asmr_deps INTERFACE capstone::capstone keystone::keystone)
        target_compile_definitions(w1_asmr_deps INTERFACE WITNESS_ASMR_ENABLED=1)

        if(DEFINED WITNESS_ASMR_CAPSTONE_DIR)
            target_include_directories(w1_asmr_deps INTERFACE "${WITNESS_ASMR_CAPSTONE_DIR}/include")
        endif()
        if(DEFINED WITNESS_ASMR_KEYSTONE_DIR)
            target_include_directories(w1_asmr_deps INTERFACE "${WITNESS_ASMR_KEYSTONE_DIR}/include")
        endif()
    endif()
endfunction()

function(w1_dep_lua)
    if(NOT WITNESS_SCRIPT)
        return()
    endif()

    if(TARGET w1::lua)
        return()
    endif()

    include("${WITNESS_CMAKE_DIR}/LuaJITBuild.cmake")

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/sol2/include/sol/sol.hpp")
        message(FATAL_ERROR "sol2 submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/sol2. Run: git submodule update --init --recursive")
    endif()

    build_luajit_from_source()

    add_library(w1_lua INTERFACE)
    add_library(w1::lua ALIAS w1_lua)
    target_include_directories(w1_lua INTERFACE
        "${WITNESS_SOURCE_DIR}/src/third_party/lua_headers"
        "${WITNESS_SOURCE_DIR}/src/third_party/sol2/include"
        ${LUAJIT_INCLUDE_DIRS}
    )
    target_link_libraries(w1_lua INTERFACE ${LUAJIT_LIBRARIES} luajit::header)
    target_compile_definitions(w1_lua INTERFACE
        SOL_NO_LUA_HPP=1
        WITNESS_SCRIPT_ENABLED=1
    )
endfunction()

function(w1_dep_jnjs)
    if(NOT WITNESS_SCRIPT)
        return()
    endif()

    if(NOT WITNESS_SCRIPT_ENGINE STREQUAL "js")
        return()
    endif()

    if(TARGET w1::jnjs)
        return()
    endif()

    if(WITNESS_USE_SYSTEM_DEPS)
        find_package(jnjs CONFIG QUIET)
        if(TARGET jnjs)
            add_library(w1_jnjs INTERFACE)
            add_library(w1::jnjs ALIAS w1_jnjs)
            target_link_libraries(w1_jnjs INTERFACE jnjs)
            target_compile_definitions(w1_jnjs INTERFACE WITNESS_SCRIPT_ENABLED=1)
            return()
        endif()
    endif()

    if(NOT EXISTS "${WITNESS_SOURCE_DIR}/src/third_party/jnjs/CMakeLists.txt")
        message(FATAL_ERROR "jnjs submodule not found at ${WITNESS_SOURCE_DIR}/src/third_party/jnjs. Run: git submodule update --init --recursive")
    endif()

    w1_set_cache_default(JNJS_ENABLE_TESTING BOOL OFF "Disable jnjs tests")

    FetchContent_Declare(jnjs SOURCE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/jnjs")
    FetchContent_MakeAvailable(jnjs)

    if(TARGET jnjs)
        add_library(w1_jnjs INTERFACE)
        add_library(w1::jnjs ALIAS w1_jnjs)
        target_link_libraries(w1_jnjs INTERFACE jnjs)
        target_compile_definitions(w1_jnjs INTERFACE WITNESS_SCRIPT_ENABLED=1)
    endif()
endfunction()

function(w1_dep_zstd)
    if(TARGET w1::zstd)
        return()
    endif()

    add_library(w1_zstd INTERFACE)
    add_library(w1::zstd ALIAS w1_zstd)

    if(NOT WITNESS_USE_SYSTEM_ZSTD)
        return()
    endif()

    set(_witness_zstd_found FALSE)
    set(_witness_zstd_provider "")

    find_package(zstd CONFIG QUIET)
    if(TARGET zstd::libzstd OR TARGET zstd::libzstd_static)
        set(_witness_zstd_found TRUE)
        set(_witness_zstd_provider "cmake-config")
    endif()

    if(NOT _witness_zstd_found)
        find_package(ZSTD QUIET)
        if(ZSTD_FOUND OR TARGET ZSTD::ZSTD OR TARGET zstd::libzstd OR TARGET zstd::libzstd_static)
            set(_witness_zstd_found TRUE)
            set(_witness_zstd_provider "cmake-module")
        endif()
    endif()

    if(NOT _witness_zstd_found)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(ZSTD_PC QUIET IMPORTED_TARGET libzstd)
            if(ZSTD_PC_FOUND)
                set(_witness_zstd_found TRUE)
                set(_witness_zstd_provider "pkg-config")
            endif()
        endif()
    endif()

    if(NOT _witness_zstd_found)
        if(WITNESS_REQUIRE_ZSTD)
            message(FATAL_ERROR "ZSTD requested but not found (set ZSTD_DIR or disable WITNESS_USE_SYSTEM_ZSTD)")
        else()
            message(STATUS "ZSTD not found; rewind compression disabled")
        endif()
        return()
    endif()

    if(WITNESS_PREFER_STATIC_ZSTD AND TARGET zstd::libzstd_static)
        target_link_libraries(w1_zstd INTERFACE zstd::libzstd_static)
    elseif(TARGET zstd::libzstd)
        target_link_libraries(w1_zstd INTERFACE zstd::libzstd)
        if(WITNESS_PREFER_STATIC_ZSTD)
            message(STATUS "ZSTD static target not found; using zstd::libzstd")
        endif()
    elseif(TARGET ZSTD::ZSTD)
        target_link_libraries(w1_zstd INTERFACE ZSTD::ZSTD)
        if(WITNESS_PREFER_STATIC_ZSTD)
            message(STATUS "ZSTD static target not found; using ZSTD::ZSTD")
        endif()
    elseif(TARGET zstd::libzstd_shared)
        target_link_libraries(w1_zstd INTERFACE zstd::libzstd_shared)
    elseif(ZSTD_LIBRARIES)
        target_link_libraries(w1_zstd INTERFACE ${ZSTD_LIBRARIES})
    elseif(TARGET PkgConfig::ZSTD_PC)
        target_link_libraries(w1_zstd INTERFACE PkgConfig::ZSTD_PC)
    endif()

    if(ZSTD_INCLUDE_DIRS)
        target_include_directories(w1_zstd INTERFACE ${ZSTD_INCLUDE_DIRS})
    endif()

    target_compile_definitions(w1_zstd INTERFACE WITNESS_REWIND_HAVE_ZSTD=1)
    if(_witness_zstd_provider)
        set(WITNESS_ZSTD_PROVIDER "${_witness_zstd_provider}" PARENT_SCOPE)
    endif()
endfunction()
