# asmrconfig.cmake - capstone/keystone configuration module
# provides functions for setting up w1asmr dependencies

include_guard()

set(WITNESS_ASMR_CAPSTONE_DIR "${W1_SOURCE_DIR}/src/third_party/capstone" CACHE PATH "capstone source directory")
set(WITNESS_ASMR_KEYSTONE_DIR "${W1_SOURCE_DIR}/src/third_party/keystone" CACHE PATH "keystone source directory")

function(validate_asmr_submodules)
    if(NOT EXISTS "${WITNESS_ASMR_CAPSTONE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR "capstone submodule not found at ${WITNESS_ASMR_CAPSTONE_DIR}. run: git submodule update --init --recursive")
    endif()
    if(NOT EXISTS "${WITNESS_ASMR_KEYSTONE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR "keystone submodule not found at ${WITNESS_ASMR_KEYSTONE_DIR}. run: git submodule update --init --recursive")
    endif()
endfunction()

function(setup_asmr_environment)
    if(NOT WITNESS_ASMR)
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

function(configure_asmr_targets)
    if(NOT WITNESS_ASMR)
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
    if(NOT WITNESS_ASMR)
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
    validate_asmr_submodules()

    add_subdirectory("${WITNESS_ASMR_CAPSTONE_DIR}" "${CMAKE_BINARY_DIR}/capstone")

    # Keystone pins CMP0051 to OLD, which newer CMake releases reject.
    # Patch the submodule sources in-place to keep the build compatible.
    set(_witness_keystone_policy_files
        "${WITNESS_ASMR_KEYSTONE_DIR}/CMakeLists.txt"
        "${WITNESS_ASMR_KEYSTONE_DIR}/llvm/CMakeLists.txt"
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
    add_subdirectory("${WITNESS_ASMR_KEYSTONE_DIR}" "${CMAKE_BINARY_DIR}/keystone")
    set(CMAKE_CXX_STANDARD "${_witness_prev_cxx_standard}")
    set(CMAKE_CXX_STANDARD_REQUIRED "${_witness_prev_cxx_standard_required}")

    configure_asmr_targets()

    set(WITNESS_ASMR_CAPSTONE_INCLUDE_DIR "${WITNESS_ASMR_CAPSTONE_DIR}/include" PARENT_SCOPE)
    set(WITNESS_ASMR_KEYSTONE_INCLUDE_DIR "${WITNESS_ASMR_KEYSTONE_DIR}/include" PARENT_SCOPE)

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
