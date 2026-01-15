# asmrconfig.cmake - capstone/keystone configuration module
# provides functions for setting up p1ll asmr dependencies

include_guard()

option(P1LL_BUILD_ASMR "Build p1ll asmr disassembler/assembler" OFF)

set(P1LL_ASMR_CAPSTONE_REPO "https://github.com/capstone-engine/capstone.git" CACHE STRING "capstone repository")
set(P1LL_ASMR_CAPSTONE_TAG "484857da5dc67f7d0e0a01c36b0ebc37a349e0fd" CACHE STRING "capstone tag")
set(P1LL_ASMR_KEYSTONE_REPO "https://github.com/keystone-engine/keystone.git" CACHE STRING "keystone repository")
set(P1LL_ASMR_KEYSTONE_TAG "fb92f32391c6cced868252167509590319eeb58b" CACHE STRING "keystone tag")

function(setup_asmr_environment)
    if(NOT P1LL_BUILD_ASMR)
        return()
    endif()

    # capstone build options
    set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE BOOL "disable capstone shared library" FORCE)
    set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE BOOL "enable capstone static library" FORCE)
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "disable capstone cstool" FORCE)
    set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "disable capstone tests" FORCE)
    set(CAPSTONE_BUILD_LEGACY_TESTS OFF CACHE BOOL "disable capstone legacy tests" FORCE)
    set(CAPSTONE_BUILD_DIET OFF CACHE BOOL "disable capstone diet library" FORCE)
    set(CAPSTONE_AARCH64_SUPPORT ON CACHE BOOL "enable capstone aarch64 support for asmr" FORCE)
    set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "enable capstone x86 support for asmr" FORCE)

    # keystone build options
    set(BUILD_LIBS_ONLY ON CACHE BOOL "build keystone library only" FORCE)
    set(KEYSTONE_BUILD_STATIC_RUNTIME ON CACHE BOOL "embed static runtime for keystone" FORCE)
endfunction()

function(fetch_asmr_dependencies)
    if(NOT P1LL_BUILD_ASMR)
        return()
    endif()

    include(FetchContent)

    FetchContent_Declare(
        capstone
        GIT_REPOSITORY ${P1LL_ASMR_CAPSTONE_REPO}
        GIT_TAG ${P1LL_ASMR_CAPSTONE_TAG}
        GIT_SHALLOW TRUE
    )

    FetchContent_GetProperties(capstone)
    if(NOT capstone_POPULATED)
        FetchContent_Populate(capstone)
        add_subdirectory(${capstone_SOURCE_DIR} ${capstone_BINARY_DIR})
    endif()

    FetchContent_Declare(
        keystone
        GIT_REPOSITORY ${P1LL_ASMR_KEYSTONE_REPO}
        GIT_TAG ${P1LL_ASMR_KEYSTONE_TAG}
        GIT_SHALLOW TRUE
    )

    FetchContent_GetProperties(keystone)
    if(NOT keystone_POPULATED)
        FetchContent_Populate(keystone)
    endif()

    # Keystone pins CMP0051 to OLD, which newer CMake releases reject.
    # Patch the fetched sources in-place to keep the build compatible.
    set(_witness_keystone_policy_files
        "${keystone_SOURCE_DIR}/CMakeLists.txt"
        "${keystone_SOURCE_DIR}/llvm/CMakeLists.txt"
    )
    foreach(_witness_policy_file IN LISTS _witness_keystone_policy_files)
        if(EXISTS "${_witness_policy_file}")
            file(READ "${_witness_policy_file}" _witness_policy_contents)
            string(REPLACE "cmake_policy(SET CMP0051 OLD)"
                "cmake_policy(SET CMP0051 NEW)"
                _witness_policy_contents
                "${_witness_policy_contents}"
            )
            file(WRITE "${_witness_policy_file}" "${_witness_policy_contents}")
        endif()
    endforeach()
    set(_witness_prev_cxx_standard "${CMAKE_CXX_STANDARD}")
    set(_witness_prev_cxx_standard_required "${CMAKE_CXX_STANDARD_REQUIRED}")
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    add_subdirectory(${keystone_SOURCE_DIR} ${keystone_BINARY_DIR})
    set(CMAKE_CXX_STANDARD "${_witness_prev_cxx_standard}")
    set(CMAKE_CXX_STANDARD_REQUIRED "${_witness_prev_cxx_standard_required}")

    set(P1LL_ASMR_CAPSTONE_INCLUDE_DIR "${capstone_SOURCE_DIR}/include" PARENT_SCOPE)
    set(P1LL_ASMR_KEYSTONE_INCLUDE_DIR "${keystone_SOURCE_DIR}/include" PARENT_SCOPE)
endfunction()

function(configure_asmr_targets)
    if(NOT P1LL_BUILD_ASMR)
        return()
    endif()

    if(TARGET capstone_static AND NOT TARGET capstone::capstone)
        add_library(capstone::capstone ALIAS capstone_static)
    elseif(TARGET capstone AND NOT TARGET capstone::capstone)
        add_library(capstone::capstone ALIAS capstone)
    endif()

    if(TARGET keystone AND NOT TARGET keystone::keystone)
        add_library(keystone::keystone ALIAS keystone)
    endif()

    if(TARGET keystone)
        target_compile_definitions(keystone PRIVATE
            LLVMInitializeAArch64TargetInfo=LLVMInitializeAArch64TargetInfo_ks
            LLVMInitializeAArch64Target=LLVMInitializeAArch64Target_ks
            LLVMInitializeAArch64TargetMC=LLVMInitializeAArch64TargetMC_ks
            LLVMInitializeAArch64AsmParser=LLVMInitializeAArch64AsmParser_ks
            LLVMInitializeX86TargetInfo=LLVMInitializeX86TargetInfo_ks
            LLVMInitializeX86Target=LLVMInitializeX86Target_ks
            LLVMInitializeX86TargetMC=LLVMInitializeX86TargetMC_ks
            LLVMInitializeX86AsmParser=LLVMInitializeX86AsmParser_ks
        )
    endif()
endfunction()

function(configure_asmr_dependencies)
    if(NOT P1LL_BUILD_ASMR)
        return()
    endif()

    set(_witness_build_shared_libs_was_set FALSE)
    if(DEFINED BUILD_SHARED_LIBS)
        set(_witness_build_shared_libs_prev "${BUILD_SHARED_LIBS}")
        set(_witness_build_shared_libs_was_set TRUE)
    endif()

    set(_witness_llvm_targets_was_set FALSE)
    if(DEFINED LLVM_TARGETS_TO_BUILD)
        set(_witness_llvm_targets_prev "${LLVM_TARGETS_TO_BUILD}")
        set(_witness_llvm_targets_was_set TRUE)
    endif()
    set(LLVM_TARGETS_TO_BUILD "AArch64;X86" CACHE STRING "keystone llvm targets" FORCE)

    if(NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM)
        set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    endif()

    set(BUILD_SHARED_LIBS OFF CACHE BOOL "force static libs for keystone" FORCE)
    setup_asmr_environment()
    fetch_asmr_dependencies()
    configure_asmr_targets()

    if(DEFINED P1LL_ASMR_CAPSTONE_INCLUDE_DIR)
        set(P1LL_ASMR_CAPSTONE_INCLUDE_DIR "${P1LL_ASMR_CAPSTONE_INCLUDE_DIR}" PARENT_SCOPE)
    endif()
    if(DEFINED P1LL_ASMR_KEYSTONE_INCLUDE_DIR)
        set(P1LL_ASMR_KEYSTONE_INCLUDE_DIR "${P1LL_ASMR_KEYSTONE_INCLUDE_DIR}" PARENT_SCOPE)
    endif()

    if(_witness_llvm_targets_was_set)
        set(LLVM_TARGETS_TO_BUILD "${_witness_llvm_targets_prev}" CACHE STRING "restore LLVM_TARGETS_TO_BUILD" FORCE)
    else()
        unset(LLVM_TARGETS_TO_BUILD CACHE)
    endif()

    if(_witness_build_shared_libs_was_set)
        set(BUILD_SHARED_LIBS "${_witness_build_shared_libs_prev}" CACHE BOOL "restore BUILD_SHARED_LIBS" FORCE)
    else()
        unset(BUILD_SHARED_LIBS CACHE)
    endif()
endfunction()
