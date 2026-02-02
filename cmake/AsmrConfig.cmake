# asmrconfig.cmake - capstone/keystone configuration module
# provides functions for setting up w1asmr dependencies

include_guard()

set(WITNESS_ASMR_CAPSTONE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/capstone" CACHE PATH "capstone source directory")
set(WITNESS_ASMR_KEYSTONE_DIR "${WITNESS_SOURCE_DIR}/src/third_party/keystone" CACHE PATH "keystone source directory")

if(NOT DEFINED WITNESS_ASMR_DISASM_ARCHES)
    set(WITNESS_ASMR_DISASM_ARCHES "X86;AARCH64;ARM;RISCV" CACHE STRING "Capstone disassembly architectures")
endif()
if(NOT DEFINED WITNESS_ASMR_ASM_ARCHES)
    set(WITNESS_ASMR_ASM_ARCHES "X86;AARCH64" CACHE STRING "Keystone assembly architectures")
endif()

function(_witness_normalize_arch_list input_list output_var)
    set(result "")
    foreach(item IN LISTS input_list)
        string(TOUPPER "${item}" item_upper)
        string(STRIP "${item_upper}" item_upper)
        if(item_upper STREQUAL "")
            continue()
        endif()
        if(item_upper STREQUAL "ARM64")
            set(item_upper "AARCH64")
        elseif(item_upper STREQUAL "RISC-V")
            set(item_upper "RISCV")
        elseif(item_upper STREQUAL "S390X" OR item_upper STREQUAL "S390")
            set(item_upper "SYSTEMZ")
        elseif(item_upper STREQUAL "THUMB")
            set(item_upper "ARM")
        endif()
        list(APPEND result "${item_upper}")
    endforeach()
    list(REMOVE_DUPLICATES result)
    set(${output_var} "${result}" PARENT_SCOPE)
endfunction()

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

    _witness_normalize_arch_list("${WITNESS_ASMR_DISASM_ARCHES}" _witness_disasm_arches)

    # capstone build options
    set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE BOOL "disable capstone shared library" FORCE)
    set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE BOOL "enable capstone static library" FORCE)
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "disable capstone cstool" FORCE)
    set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "disable capstone tests" FORCE)
    set(CAPSTONE_BUILD_LEGACY_TESTS OFF CACHE BOOL "disable capstone legacy tests" FORCE)
    set(CAPSTONE_BUILD_DIET OFF CACHE BOOL "disable capstone diet library" FORCE)
    set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "disable capstone default architectures" FORCE)
    set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "disable capstone arm support for asmr" FORCE)
    set(CAPSTONE_AARCH64_SUPPORT OFF CACHE BOOL "disable capstone aarch64 support for asmr" FORCE)
    set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "disable capstone mips support for asmr" FORCE)
    set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "disable capstone ppc support for asmr" FORCE)
    set(CAPSTONE_X86_SUPPORT OFF CACHE BOOL "disable capstone x86 support for asmr" FORCE)
    set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "disable capstone sparc support for asmr" FORCE)
    set(CAPSTONE_SYSTEMZ_SUPPORT OFF CACHE BOOL "disable capstone systemz support for asmr" FORCE)
    set(CAPSTONE_RISCV_SUPPORT OFF CACHE BOOL "disable capstone riscv support for asmr" FORCE)
    set(CAPSTONE_WASM_SUPPORT OFF CACHE BOOL "disable capstone wasm support for asmr" FORCE)
    foreach(_witness_arch IN LISTS _witness_disasm_arches)
        if(_witness_arch STREQUAL "ARM")
            set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "enable capstone arm support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "AARCH64")
            set(CAPSTONE_AARCH64_SUPPORT ON CACHE BOOL "enable capstone aarch64 support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "MIPS")
            set(CAPSTONE_MIPS_SUPPORT ON CACHE BOOL "enable capstone mips support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "PPC")
            set(CAPSTONE_PPC_SUPPORT ON CACHE BOOL "enable capstone ppc support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "X86")
            set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "enable capstone x86 support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "SPARC")
            set(CAPSTONE_SPARC_SUPPORT ON CACHE BOOL "enable capstone sparc support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "SYSTEMZ")
            set(CAPSTONE_SYSTEMZ_SUPPORT ON CACHE BOOL "enable capstone systemz support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "RISCV")
            set(CAPSTONE_RISCV_SUPPORT ON CACHE BOOL "enable capstone riscv support for asmr" FORCE)
        elseif(_witness_arch STREQUAL "WASM")
            set(CAPSTONE_WASM_SUPPORT ON CACHE BOOL "enable capstone wasm support for asmr" FORCE)
        else()
            message(WARNING "Unknown disassembly architecture '${_witness_arch}' in WITNESS_ASMR_DISASM_ARCHES")
        endif()
    endforeach()

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
        _witness_normalize_arch_list("${WITNESS_ASMR_ASM_ARCHES}" _witness_asm_arches)
        set(_witness_keystone_defs "")
        foreach(_witness_arch IN LISTS _witness_asm_arches)
            if(_witness_arch STREQUAL "AARCH64")
                list(APPEND _witness_keystone_defs
                    LLVMInitializeAArch64TargetInfo=LLVMInitializeAArch64TargetInfo_ks
                    LLVMInitializeAArch64Target=LLVMInitializeAArch64Target_ks
                    LLVMInitializeAArch64TargetMC=LLVMInitializeAArch64TargetMC_ks
                    LLVMInitializeAArch64AsmParser=LLVMInitializeAArch64AsmParser_ks
                )
            elseif(_witness_arch STREQUAL "X86")
                list(APPEND _witness_keystone_defs
                    LLVMInitializeX86TargetInfo=LLVMInitializeX86TargetInfo_ks
                    LLVMInitializeX86Target=LLVMInitializeX86Target_ks
                    LLVMInitializeX86TargetMC=LLVMInitializeX86TargetMC_ks
                    LLVMInitializeX86AsmParser=LLVMInitializeX86AsmParser_ks
                )
            elseif(_witness_arch STREQUAL "ARM")
                list(APPEND _witness_keystone_defs
                    LLVMInitializeARMTargetInfo=LLVMInitializeARMTargetInfo_ks
                    LLVMInitializeARMTarget=LLVMInitializeARMTarget_ks
                    LLVMInitializeARMTargetMC=LLVMInitializeARMTargetMC_ks
                    LLVMInitializeARMAsmParser=LLVMInitializeARMAsmParser_ks
                )
            elseif(_witness_arch STREQUAL "MIPS")
                list(APPEND _witness_keystone_defs
                    LLVMInitializeMipsTargetInfo=LLVMInitializeMipsTargetInfo_ks
                    LLVMInitializeMipsTarget=LLVMInitializeMipsTarget_ks
                    LLVMInitializeMipsTargetMC=LLVMInitializeMipsTargetMC_ks
                    LLVMInitializeMipsAsmParser=LLVMInitializeMipsAsmParser_ks
                )
            elseif(_witness_arch STREQUAL "RISCV")
                list(APPEND _witness_keystone_defs
                    LLVMInitializeRISCVTargetInfo=LLVMInitializeRISCVTargetInfo_ks
                    LLVMInitializeRISCVTarget=LLVMInitializeRISCVTarget_ks
                    LLVMInitializeRISCVTargetMC=LLVMInitializeRISCVTargetMC_ks
                    LLVMInitializeRISCVAsmParser=LLVMInitializeRISCVAsmParser_ks
                )
            else()
                message(WARNING "Unknown assembly architecture '${_witness_arch}' in WITNESS_ASMR_ASM_ARCHES")
            endif()
        endforeach()
        if(_witness_keystone_defs)
            target_compile_definitions(keystone PRIVATE ${_witness_keystone_defs})
        endif()
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

    set(_witness_llvm_enable_zlib_was_set FALSE)
    if(DEFINED LLVM_ENABLE_ZLIB)
        set(_witness_llvm_enable_zlib_prev "${LLVM_ENABLE_ZLIB}")
        set(_witness_llvm_enable_zlib_was_set TRUE)
    endif()
    set(_witness_llvm_enable_zstd_was_set FALSE)
    if(DEFINED LLVM_ENABLE_ZSTD)
        set(_witness_llvm_enable_zstd_prev "${LLVM_ENABLE_ZSTD}")
        set(_witness_llvm_enable_zstd_was_set TRUE)
    endif()

    set(_witness_llvm_targets_was_set FALSE)
    if(DEFINED LLVM_TARGETS_TO_BUILD)
        set(_witness_llvm_targets_prev "${LLVM_TARGETS_TO_BUILD}")
        set(_witness_llvm_targets_was_set TRUE)
    endif()
    _witness_normalize_arch_list("${WITNESS_ASMR_ASM_ARCHES}" _witness_asm_arches)
    set(_witness_llvm_targets "")
    foreach(_witness_arch IN LISTS _witness_asm_arches)
        if(_witness_arch STREQUAL "AARCH64")
            list(APPEND _witness_llvm_targets "AArch64")
        elseif(_witness_arch STREQUAL "X86")
            list(APPEND _witness_llvm_targets "X86")
        elseif(_witness_arch STREQUAL "ARM")
            list(APPEND _witness_llvm_targets "ARM")
        elseif(_witness_arch STREQUAL "RISCV")
            list(APPEND _witness_llvm_targets "RISCV")
        elseif(_witness_arch STREQUAL "MIPS")
            list(APPEND _witness_llvm_targets "Mips")
        else()
            message(WARNING "Unknown assembly architecture '${_witness_arch}' in WITNESS_ASMR_ASM_ARCHES")
        endif()
    endforeach()
    if(NOT _witness_llvm_targets)
        list(APPEND _witness_llvm_targets "X86")
        message(WARNING "WITNESS_ASMR_ASM_ARCHES is empty; defaulting LLVM_TARGETS_TO_BUILD to X86")
    endif()
    list(REMOVE_DUPLICATES _witness_llvm_targets)
    string(JOIN ";" _witness_llvm_targets_joined ${_witness_llvm_targets})
    set(LLVM_TARGETS_TO_BUILD "${_witness_llvm_targets_joined}" CACHE STRING "keystone llvm targets" FORCE)

    if(NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM)
        set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    endif()

    set(LLVM_ENABLE_ZLIB OFF CACHE BOOL "disable zlib for keystone llvm" FORCE)
    set(LLVM_ENABLE_ZSTD OFF CACHE BOOL "disable zstd for keystone llvm" FORCE)
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
    set(_wincross_native_cc "$ENV{WINCROSS_NATIVE_CC}")
    set(_wincross_native_cxx "$ENV{WINCROSS_NATIVE_CXX}")
    set(_wincross_prev_cc "$ENV{CC}")
    set(_wincross_prev_cxx "$ENV{CXX}")
    if(_wincross_native_cc)
        set(ENV{CC} "${_wincross_native_cc}")
    endif()
    if(_wincross_native_cxx)
        set(ENV{CXX} "${_wincross_native_cxx}")
    endif()
    add_subdirectory("${WITNESS_ASMR_KEYSTONE_DIR}" "${CMAKE_BINARY_DIR}/keystone")
    if(DEFINED _wincross_prev_cc)
        set(ENV{CC} "${_wincross_prev_cc}")
    else()
        set(ENV{CC} "")
    endif()
    if(DEFINED _wincross_prev_cxx)
        set(ENV{CXX} "${_wincross_prev_cxx}")
    else()
        set(ENV{CXX} "")
    endif()
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

    if(_witness_llvm_enable_zlib_was_set)
        set(LLVM_ENABLE_ZLIB "${_witness_llvm_enable_zlib_prev}" CACHE BOOL "restore LLVM_ENABLE_ZLIB" FORCE)
    else()
        unset(LLVM_ENABLE_ZLIB CACHE)
    endif()
    if(_witness_llvm_enable_zstd_was_set)
        set(LLVM_ENABLE_ZSTD "${_witness_llvm_enable_zstd_prev}" CACHE BOOL "restore LLVM_ENABLE_ZSTD" FORCE)
    else()
        unset(LLVM_ENABLE_ZSTD CACHE)
    endif()

    if(_witness_build_shared_libs_was_set)
        set(BUILD_SHARED_LIBS "${_witness_build_shared_libs_prev}" CACHE BOOL "restore BUILD_SHARED_LIBS" FORCE)
    else()
        unset(BUILD_SHARED_LIBS CACHE)
    endif()
endfunction()
