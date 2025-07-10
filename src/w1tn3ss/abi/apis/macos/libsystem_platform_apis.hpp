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
 * @brief libsystem_platform.dylib api definitions
 *
 * covers platform-optimized apis:
 * - optimized string functions (__platform_strlen, __platform_strcmp, etc.)
 * - optimized memory functions (__platform_memcpy, __platform_memmove, etc.)
 * - atomic operations (OSAtomicAdd32, OSAtomicCompareAndSwap64, etc.)
 * - synchronization primitives (os_unfair_lock, OSSpinLock, etc.)
 * - low-level platform utilities
 */

static const std::vector<api_info> macos_libsystem_platform_apis = {
    // ===== OPTIMIZED STRING FUNCTIONS =====
    {.name = "__platform_strlen",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "length", .param_type = param_info::type::SIZE},
     .description = "optimized string length calculation",
     .headers = {"string.h"}},
    
    {.name = "__platform_strnlen",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "maxlen", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "length", .param_type = param_info::type::SIZE},
     .description = "optimized string length with maximum",
     .headers = {"string.h"}},
    
    {.name = "__platform_strcmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s1", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "s2", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "optimized string comparison",
     .headers = {"string.h"}},
    
    {.name = "__platform_strncmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s1", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "s2", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "optimized string comparison with length",
     .headers = {"string.h"}},
    
    {.name = "__platform_strcpy",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "src", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "dest", .param_type = param_info::type::POINTER},
     .description = "optimized string copy (unsafe - no bounds checking)",
     .headers = {"string.h"},
     .security_notes = {"no bounds checking, can cause buffer overflow"}},
    
    {.name = "__platform_strncpy",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "src", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "dest", .param_type = param_info::type::POINTER},
     .description = "optimized string copy with length limit",
     .headers = {"string.h"}},
    
    {.name = "__platform_strlcpy",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "src", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "copied", .param_type = param_info::type::SIZE},
     .description = "optimized safe string copy",
     .headers = {"string.h"}},
    
    {.name = "__platform_strlcat",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
          {.name = "src", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "total_length", .param_type = param_info::type::SIZE},
     .description = "optimized safe string concatenation",
     .headers = {"string.h"}},
    
    {.name = "__platform_strchr",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "found", .param_type = param_info::type::POINTER},
     .description = "optimized character search in string",
     .headers = {"string.h"}},
    
    {.name = "__platform_strstr",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::STRING_MANIPULATION,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "haystack", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
          {.name = "needle", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "found", .param_type = param_info::type::POINTER},
     .description = "optimized substring search",
     .headers = {"string.h"}},
    
    // ===== OPTIMIZED MEMORY FUNCTIONS =====
    {.name = "__platform_memcpy",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "src", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "dest", .param_type = param_info::type::POINTER},
     .description = "optimized memory copy (non-overlapping)",
     .headers = {"string.h"},
     .security_notes = {"undefined behavior if memory regions overlap"}},
    
    {.name = "__platform_memmove",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "src", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "dest", .param_type = param_info::type::POINTER},
     .description = "optimized memory move (handles overlapping)",
     .headers = {"string.h"}},
    
    {.name = "__platform_memset",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "s", .param_type = param_info::type::POINTER},
     .description = "optimized memory fill",
     .headers = {"string.h"}},
    
    {.name = "__platform_bzero",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "optimized memory zero",
     .headers = {"strings.h"}},
    
    {.name = "__platform_memcmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s1", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "s2", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "optimized memory comparison",
     .headers = {"string.h"}},
    
    {.name = "__platform_memchr",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "s", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "found", .param_type = param_info::type::POINTER},
     .description = "optimized byte search in memory",
     .headers = {"string.h"}},
    
    {.name = "__platform_memccpy",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "dest", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "src", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "n", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "after_c", .param_type = param_info::type::POINTER},
     .description = "copy memory until character found",
     .headers = {"string.h"}},
    
    {.name = "__platform_memset_pattern4",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "b", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "pattern", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "optimized memory fill with 4-byte pattern",
     .headers = {"string.h"}},
    
    {.name = "__platform_memset_pattern8",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "b", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "pattern", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "optimized memory fill with 8-byte pattern",
     .headers = {"string.h"}},
    
    {.name = "__platform_memset_pattern16",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "b", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "pattern", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "optimized memory fill with 16-byte pattern",
     .headers = {"string.h"}},
    
    // ===== ATOMIC OPERATIONS =====
    {.name = "_OSAtomicAdd32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "amount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit addition",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicAdd32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "amount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit addition with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicAdd64",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "amount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 64-bit addition",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicAdd64Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "amount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 64-bit addition with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicIncrement32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit increment",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicIncrement32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit increment with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicIncrement64",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 64-bit increment",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicIncrement64Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 64-bit increment with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicDecrement32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit decrement",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicDecrement32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit decrement with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicDecrement64",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 64-bit decrement",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicDecrement64Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "new_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 64-bit decrement with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicCompareAndSwap32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "old_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "new_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
     .description = "atomic 32-bit compare and swap",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicCompareAndSwap32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "old_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "new_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
     .description = "atomic 32-bit compare and swap with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicCompareAndSwap64",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "old_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "new_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
     .description = "atomic 64-bit compare and swap",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicCompareAndSwap64Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "old_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "new_value", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
     .description = "atomic 64-bit compare and swap with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicCompareAndSwapPtr",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "old_value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "new_value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
     .description = "atomic pointer compare and swap",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicCompareAndSwapPtrBarrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "old_value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "new_value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
     .description = "atomic pointer compare and swap with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicAnd32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "old_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit AND operation",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicAnd32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "old_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit AND operation with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicOr32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "old_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit OR operation",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicOr32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "old_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit OR operation with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicXor32",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "old_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit XOR operation",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSAtomicXor32Barrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "mask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "value", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "old_value", .param_type = param_info::type::INTEGER},
     .description = "atomic 32-bit XOR operation with memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    {.name = "_OSMemoryBarrier",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "full memory barrier",
     .headers = {"libkern/OSAtomic.h"}},
    
    // ===== LOCK OPERATIONS =====
    {.name = "_os_unfair_lock_lock",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "acquire unfair lock (modern macOS lock)",
     .headers = {"os/lock.h"}},
    
    {.name = "_os_unfair_lock_unlock",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "release unfair lock",
     .headers = {"os/lock.h"}},
    
    {.name = "_os_unfair_lock_trylock",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "acquired", .param_type = param_info::type::BOOLEAN},
     .description = "try to acquire unfair lock",
     .headers = {"os/lock.h"}},
    
    {.name = "_os_unfair_lock_assert_owner",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "assert current thread owns lock",
     .headers = {"os/lock.h"}},
    
    {.name = "_os_unfair_lock_assert_not_owner",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "assert current thread does not own lock",
     .headers = {"os/lock.h"}},
    
    {.name = "_OSSpinLockLock",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "acquire spin lock (deprecated)",
     .headers = {"libkern/OSAtomic.h"},
     .security_notes = {"deprecated: use os_unfair_lock instead"}},
    
    {.name = "_OSSpinLockUnlock",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "release spin lock (deprecated)",
     .headers = {"libkern/OSAtomic.h"},
     .security_notes = {"deprecated: use os_unfair_lock instead"}},
    
    {.name = "_OSSpinLockTry",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::SYNCHRONIZATION,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::THREAD_SAFE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "lock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}},
     .return_value = {.name = "acquired", .param_type = param_info::type::BOOLEAN},
     .description = "try to acquire spin lock (deprecated)",
     .headers = {"libkern/OSAtomic.h"},
     .security_notes = {"deprecated: use os_unfair_lock instead"}},
    
    // ===== MISCELLANEOUS PLATFORM FUNCTIONS =====
    {.name = "_setjmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::PROCESS_CONTROL,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "env", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "save program state for longjmp",
     .headers = {"setjmp.h"}},
    
    {.name = "_longjmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::PROCESS_CONTROL,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "env", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "val", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "restore program state from setjmp",
     .headers = {"setjmp.h"}},
    
    {.name = "__setjmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::PROCESS_CONTROL,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "env", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "save program state (internal)",
     .headers = {"setjmp.h"}},
    
    {.name = "__longjmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::PROCESS_CONTROL,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "env", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "val", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "restore program state (internal)",
     .headers = {"setjmp.h"}},
    
    {.name = "_sigsetjmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::PROCESS_CONTROL,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "env", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "savemask", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "save program state with signal mask",
     .headers = {"setjmp.h"}},
    
    {.name = "_siglongjmp",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::PROCESS_CONTROL,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "env", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "val", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "restore program state with signal mask",
     .headers = {"setjmp.h"}},
    
    {.name = "_sys_icache_invalidate",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "start", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "invalidate instruction cache",
     .headers = {"libkern/OSCacheControl.h"}},
    
    {.name = "_sys_dcache_flush",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "start", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "flush data cache",
     .headers = {"libkern/OSCacheControl.h"}},
    
    {.name = "_sys_cache_control",
     .module = "libsystem_platform.dylib",
     .api_category = api_info::category::MEMORY_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "func", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
          {.name = "start", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "generic cache control",
     .headers = {"libkern/OSCacheControl.h"}},
};

} // namespace w1::abi::apis::macos