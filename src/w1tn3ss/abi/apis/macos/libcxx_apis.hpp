#pragma once

#include "abi/api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::macos {

// determine macOS calling convention based on architecture
#if defined(__x86_64__)
#define MACOS_API_CONVENTION calling_convention_id::X86_64_SYSTEM_V
#elif defined(__aarch64__)
#define MACOS_API_CONVENTION calling_convention_id::AARCH64_AAPCS
#elif defined(__arm__)
#define MACOS_API_CONVENTION calling_convention_id::ARM32_AAPCS
#elif defined(__i386__)
#define MACOS_API_CONVENTION calling_convention_id::X86_CDECL
#else
#warning "Unknown macOS architecture, using UNKNOWN calling convention"
#define MACOS_API_CONVENTION calling_convention_id::UNKNOWN
#endif

/**
 * @brief libc++abi.dylib and libc++.1.dylib api definitions
 *
 * covers c++ runtime and standard library apis:
 * - exception handling (__cxa_throw, __cxa_begin_catch, etc.)
 * - memory management (operator new/delete variants)
 * - rtti support (__dynamic_cast, __cxa_demangle)
 * - guard variables for static initialization
 * - personality functions for stack unwinding
 * - standard library exception functions
 */

static const std::vector<api_info> macos_libcxx_apis = {
    // ===== EXCEPTION HANDLING APIs =====
    {.name = "___cxa_throw",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "thrown_object",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN},
          {.name = "tinfo", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "throw c++ exception",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_begin_catch",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "exc_obj", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "object", .param_type = param_info::type::POINTER},
     .description = "begin exception catch block",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_end_catch",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "end exception catch block",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_rethrow",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "rethrow current exception",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_allocate_exception",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "thrown_size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "exception_ptr", .param_type = param_info::type::POINTER},
     .description = "allocate memory for exception object",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_free_exception",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "thrown_object",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "free exception memory",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_current_exception_type",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "type_info", .param_type = param_info::type::POINTER},
     .description = "get current exception type info",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_bad_cast",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "throw bad_cast exception",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_bad_typeid",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "throw bad_typeid exception",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_throw_bad_array_new_length",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "throw bad_array_new_length exception",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_pure_virtual",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "pure virtual function called",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_deleted_virtual",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "deleted virtual function called",
     .headers = {"cxxabi.h"}},

    // ===== STATIC INITIALIZATION GUARDS =====
    {.name = "___cxa_guard_acquire",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "guard_object",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "acquired", .param_type = param_info::type::INTEGER},
     .description = "acquire guard for static initialization",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_guard_release",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "guard_object",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "release guard after static initialization",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_guard_abort",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "guard_object",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "abort static initialization",
     .headers = {"cxxabi.h"}},

    // ===== RTTI AND TYPE SUPPORT =====
    {.name = "___dynamic_cast",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "src_ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "src_type", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "dst_type", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "src2dst_offset",
           .param_type = param_info::type::INTEGER,
           .param_direction = param_info::direction::IN}},
     .return_value = {.name = "casted_ptr", .param_type = param_info::type::POINTER},
     .description = "perform dynamic_cast operation",
     .headers = {"cxxabi.h"}},

    {.name = "___cxa_demangle",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mangled_name",
           .param_type = param_info::type::STRING,
           .param_direction = param_info::direction::IN},
          {.name = "output_buffer",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN_OUT},
          {.name = "length", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
          {.name = "status", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}},
     .return_value = {.name = "demangled", .param_type = param_info::type::POINTER},
     .description = "demangle c++ symbol name",
     .headers = {"cxxabi.h"}},

    // ===== PERSONALITY AND UNWINDING =====
    {.name = "___gxx_personality_v0",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "version", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "actions", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "exception_class",
           .param_type = param_info::type::INTEGER,
           .param_direction = param_info::direction::IN},
          {.name = "exception_object",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN},
          {.name = "context", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "c++ exception personality function",
     .headers = {"unwind.h"}},

    // ===== MEMORY MANAGEMENT - OPERATOR NEW =====
    {.name = "__Znwm",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "operator new(size_t)",
     .headers = {"new"}},

    {.name = "__Znam",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "operator new[](size_t)",
     .headers = {"new"}},

    {.name = "__ZnwmRKSt9nothrow_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
          {.name = "nothrow", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "operator new(size_t, nothrow)",
     .headers = {"new"}},

    {.name = "__ZnamRKSt9nothrow_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
          {.name = "nothrow", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "operator new[](size_t, nothrow)",
     .headers = {"new"}},

    {.name = "__ZnwmSt11align_val_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
          {.name = "alignment", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "operator new(size_t, align_val_t)",
     .headers = {"new"}},

    {.name = "__ZnamSt11align_val_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
          {.name = "alignment", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "operator new[](size_t, align_val_t)",
     .headers = {"new"}},

    // ===== MEMORY MANAGEMENT - OPERATOR DELETE =====
    {.name = "__ZdlPv",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete(void*)",
     .headers = {"new"}},

    {.name = "__ZdaPv",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete[](void*)",
     .headers = {"new"}},

    {.name = "__ZdlPvm",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete(void*, size_t)",
     .headers = {"new"}},

    {.name = "__ZdaPvm",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete[](void*, size_t)",
     .headers = {"new"}},

    {.name = "__ZdlPvRKSt9nothrow_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "nothrow", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete(void*, nothrow)",
     .headers = {"new"}},

    {.name = "__ZdaPvRKSt9nothrow_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "nothrow", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete[](void*, nothrow)",
     .headers = {"new"}},

    {.name = "__ZdlPvSt11align_val_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "alignment", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete(void*, align_val_t)",
     .headers = {"new"}},

    {.name = "__ZdaPvSt11align_val_t",
     .module = "libc++abi.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "alignment", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "operator delete[](void*, align_val_t)",
     .headers = {"new"}},

    // ===== STANDARD LIBRARY EXCEPTION FUNCTIONS =====
    {.name = "__ZSt17__throw_bad_allocv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "throw std::bad_alloc",
     .headers = {"new"}},

    {.name = "__ZSt9terminatev",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "std::terminate()",
     .headers = {"exception"}},

    {.name = "__ZSt14set_terminatePFvvE",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "handler", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "old_handler", .param_type = param_info::type::POINTER},
     .description = "std::set_terminate(handler)",
     .headers = {"exception"}},

    {.name = "__ZSt13get_terminatev",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "handler", .param_type = param_info::type::POINTER},
     .description = "std::get_terminate()",
     .headers = {"exception"}},

    {.name = "__ZSt10unexpectedv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "std::unexpected()",
     .headers = {"exception"}},

    {.name = "__ZSt14set_unexpectedPFvvE",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "handler", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "old_handler", .param_type = param_info::type::POINTER},
     .description = "std::set_unexpected(handler)",
     .headers = {"exception"}},

    {.name = "__ZSt13get_unexpectedv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "handler", .param_type = param_info::type::POINTER},
     .description = "std::get_unexpected()",
     .headers = {"exception"}},

    {.name = "__ZSt18uncaught_exceptionv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "uncaught", .param_type = param_info::type::BOOLEAN},
     .description = "std::uncaught_exception()",
     .headers = {"exception"}},

    {.name = "__ZSt19uncaught_exceptionsv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "count", .param_type = param_info::type::INTEGER},
     .description = "std::uncaught_exceptions()",
     .headers = {"exception"}},

    {.name = "__ZSt17current_exceptionv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "exception_ptr", .param_type = param_info::type::POINTER},
     .description = "std::current_exception()",
     .headers = {"exception"}},

    {.name = "__ZSt17rethrow_exceptionSt13exception_ptr",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MISC,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "std::rethrow_exception(exception_ptr)",
     .headers = {"exception"}},

    // ===== MEMORY HANDLER FUNCTIONS =====
    {.name = "__ZSt15get_new_handlerv",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "handler", .param_type = param_info::type::POINTER},
     .description = "std::get_new_handler()",
     .headers = {"new"}},

    {.name = "__ZSt15set_new_handlerPFvvE",
     .module = "libc++.1.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "handler", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "old_handler", .param_type = param_info::type::POINTER},
     .description = "std::set_new_handler(handler)",
     .headers = {"new"}},
};

} // namespace w1::abi::apis::macos