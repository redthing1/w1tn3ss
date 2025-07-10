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
 * @brief libdyld.dylib api definitions
 *
 * covers dynamic library loading apis:
 * - library loading/unloading (dlopen, dlclose)
 * - symbol resolution (dlsym, dladdr)
 * - error handling (dlerror)
 */

static const std::vector<api_info> macos_libdyld_apis = {
    // ===== DYNAMIC LOADING APIs =====
    {.name = "_dlopen",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
              static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "filename", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
          {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
     .description = "open dynamic library",
     .cleanup_api = "_dlclose",
     .headers = {"dlfcn.h"}},
    {.name = "_dlclose",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE) |
              static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "handle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "close dynamic library",
     .headers = {"dlfcn.h"}},
    {.name = "_dlsym",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "handle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
          {.name = "symbol", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "address", .param_type = param_info::type::POINTER},
     .description = "get symbol from library",
     .headers = {"dlfcn.h"}},
    {.name = "_dladdr",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "addr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
          {.name = "info", .param_type = param_info::type::STRUCT, .param_direction = param_info::direction::OUT}},
     .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
     .description = "get info about address",
     .headers = {"dlfcn.h"}},
    {.name = "_dlerror",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters = {},
     .return_value = {.name = "error_msg", .param_type = param_info::type::STRING},
     .description = "get last dl error message",
     .headers = {"dlfcn.h"}},
    {.name = "_dlopen_preflight",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = 0,
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "path", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "result", .param_type = param_info::type::BOOLEAN},
     .description = "check if library can be loaded",
     .headers = {"dlfcn.h"}},
    {.name = "_dlopen_from",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
              static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "path", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
          {.name = "mode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
          {.name = "addressInImageWhereSymbolIsBeingLookedUp",
           .param_type = param_info::type::POINTER,
           .param_direction = param_info::direction::IN}},
     .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
     .description = "open library from specific context",
     .cleanup_api = "_dlclose",
     .headers = {"dlfcn.h"}},
    {.name = "_dlopen_audited",
     .module = "libdyld.dylib",
     .api_category = api_info::category::LIBRARY_LOADING,
     .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
              static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
     .convention = MACOS_API_CONVENTION,
     .parameters =
         {{.name = "filename", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
          {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
     .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
     .description = "open library with auditing",
     .cleanup_api = "_dlclose",
     .headers = {"dlfcn.h"}}
};

} // namespace w1::abi::apis::macos