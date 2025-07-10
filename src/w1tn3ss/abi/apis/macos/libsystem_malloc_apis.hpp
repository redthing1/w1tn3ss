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
 * @brief libsystem_malloc.dylib api definitions
 *
 * covers heap management apis:
 * - memory allocation (malloc, calloc, realloc)
 * - memory deallocation (free)
 * - memory zone management
 */

static const std::vector<api_info> macos_libsystem_malloc_apis = {
    // ===== HEAP MANAGEMENT APIs =====
    {.name = "_malloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "allocate memory",
     .cleanup_api = "_free",
     .headers = {"stdlib.h"}},
    {.name = "_free",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "free allocated memory",
     .headers = {"stdlib.h"}},
    {.name = "_calloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "nmemb", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "allocate and zero memory",
     .cleanup_api = "_free",
     .headers = {"stdlib.h"}},
    {.name = "_realloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
              static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "new_ptr", .param_type = param_info::type::POINTER},
     .description = "resize allocated memory",
     .headers = {"stdlib.h"}},
    {.name = "_reallocf",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
              static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "new_ptr", .param_type = param_info::type::POINTER},
     .description = "resize allocated memory (frees on failure)",
     .headers = {"stdlib.h"}},
    {.name = "_valloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "allocate page-aligned memory",
     .cleanup_api = "_free",
     .headers = {"stdlib.h"}},
    {.name = "_posix_memalign",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "memptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
          {.name = "alignment", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "allocate aligned memory",
     .headers = {"stdlib.h"}},
    {.name = "_malloc_size",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "size", .param_type = param_info::type::SIZE},
     .description = "get size of allocated memory block",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_good_size",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "good_size", .param_type = param_info::type::SIZE},
     .description = "round up to efficient allocation size",
     .headers = {"malloc/malloc.h"}},
    
    // memory zone management
    {.name = "_malloc_zone_malloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "zone", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "allocate memory from specific zone",
     .cleanup_api = "_malloc_zone_free",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_zone_free",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "zone", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "free memory in specific zone",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_zone_calloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "zone", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "num_items", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
     .description = "allocate and zero memory from specific zone",
     .cleanup_api = "_malloc_zone_free",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_zone_realloc",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
              static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "zone", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "new_ptr", .param_type = param_info::type::POINTER},
     .description = "resize memory in specific zone",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_default_zone",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "zone", .param_type = param_info::type::POINTER},
     .description = "get default malloc zone",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_create_zone",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "start_size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
          {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "zone", .param_type = param_info::type::POINTER},
     .description = "create new malloc zone",
     .cleanup_api = "_malloc_destroy_zone",
     .headers = {"malloc/malloc.h"}},
    {.name = "_malloc_destroy_zone",
     .module = "libsystem_malloc.dylib",
     .api_category = api_info::category::HEAP_MANAGEMENT,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "zone", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "void", .param_type = param_info::type::VOID},
     .description = "destroy malloc zone",
     .headers = {"malloc/malloc.h"}}
};

} // namespace w1::abi::apis::macos