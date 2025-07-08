#pragma once

#include "abi/api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::windows {

// determine windows calling convention based on architecture
#if defined(_M_X64) || defined(__x86_64__)
#define WINDOWS_API_CONVENTION calling_convention_id::X86_64_MICROSOFT
#elif defined(_M_IX86) || defined(__i386__)
#define WINDOWS_API_CONVENTION calling_convention_id::X86_STDCALL
#else
#define WINDOWS_API_CONVENTION calling_convention_id::UNKNOWN
#endif

/**
 * @brief psapi.dll api definitions
 *
 * covers windows process status apis:
 * - process enumeration and information
 * - module enumeration and details
 * - memory usage statistics
 * - performance counters
 * - working set information
 * - device driver information
 */

static const std::vector<api_info> windows_psapi_apis = {
    // === PROCESS ENUMERATION ===

    api_info{
        .name = "EnumProcesses",
        .module = "psapi.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "lpidProcess",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "lpcbNeeded",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve list of process identifiers",
        .security_notes = {"process discovery capability", "system reconnaissance"},
        .related_apis = {"OpenProcess", "EnumProcessModules", "GetProcessImageFileName"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetProcessImageFileNameW",
        .module = "psapi.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpImageFileName",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve device-form path of process executable",
        .related_apis = {"EnumProcesses", "GetModuleFileNameEx", "QueryFullProcessImageName"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetProcessMemoryInfo",
        .module = "psapi.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "Process", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "ppsmemCounters",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve memory usage information for process",
        .related_apis = {"GetPerformanceInfo", "GetWsChanges"},
        .headers = {"windows.h", "psapi.h"}
    },

    // === MODULE ENUMERATION ===

    api_info{
        .name = "EnumProcessModules",
        .module = "psapi.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lphModule",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "lpcbNeeded",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve handles for modules in process",
        .security_notes = {"module discovery capability", "dll enumeration for analysis"},
        .related_apis = {"GetModuleInformation", "GetModuleFileNameEx", "GetModuleBaseName"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "EnumProcessModulesEx",
        .module = "psapi.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lphModule",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "lpcbNeeded",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "dwFilterFlag",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve handles for modules in process with filtering",
        .security_notes = {"module discovery with wow64 filtering", "architecture-aware enumeration"},
        .related_apis = {"EnumProcessModules", "GetModuleInformation"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetModuleInformation",
        .module = "psapi.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "hModule", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpmodinfo",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve information about module",
        .related_apis = {"EnumProcessModules", "GetModuleFileNameEx"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetModuleFileNameExW",
        .module = "psapi.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "hModule", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpFilename",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve full path of module file",
        .related_apis = {"GetModuleBaseName", "GetModuleInformation", "EnumProcessModules"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetModuleBaseNameW",
        .module = "psapi.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "hModule", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpBaseName",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve base name of module",
        .related_apis = {"GetModuleFileNameEx", "GetModuleInformation"},
        .headers = {"windows.h", "psapi.h"}
    },

    // === WORKING SET INFORMATION ===

    api_info{
        .name = "QueryWorkingSet",
        .module = "psapi.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "pv", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve working set information for process",
        .related_apis = {"QueryWorkingSetEx", "GetProcessMemoryInfo"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "QueryWorkingSetEx",
        .module = "psapi.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "pv", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve extended working set information",
        .related_apis = {"QueryWorkingSet", "GetWsChanges"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetWsChanges",
        .module = "psapi.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpWatchInfo",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve working set changes since last call",
        .related_apis = {"InitializeProcessForWsWatch", "QueryWorkingSetEx"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "InitializeProcessForWsWatch",
        .module = "psapi.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "initialize process for working set monitoring",
        .related_apis = {"GetWsChanges", "QueryWorkingSetEx"},
        .headers = {"windows.h", "psapi.h"}
    },

    // === DEVICE DRIVER ENUMERATION ===

    api_info{
        .name = "EnumDeviceDrivers",
        .module = "psapi.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "lpImageBase",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "lpcbNeeded",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve list of device driver load addresses",
        .security_notes = {"kernel driver enumeration", "rootkit detection capability"},
        .related_apis = {"GetDeviceDriverBaseName", "GetDeviceDriverFileName"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetDeviceDriverBaseNameW",
        .module = "psapi.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ImageBase",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "lpBaseName",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve base name of device driver",
        .related_apis = {"EnumDeviceDrivers", "GetDeviceDriverFileName"},
        .headers = {"windows.h", "psapi.h"}
    },

    api_info{
        .name = "GetDeviceDriverFileNameW",
        .module = "psapi.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ImageBase",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "lpFileName",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve file name of device driver",
        .related_apis = {"EnumDeviceDrivers", "GetDeviceDriverBaseName"},
        .headers = {"windows.h", "psapi.h"}
    },

    // === PERFORMANCE INFORMATION ===

    api_info{
        .name = "GetPerformanceInfo",
        .module = "psapi.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "pPerformanceInformation",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "cb", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve system performance information",
        .related_apis = {"GetProcessMemoryInfo", "EnumProcesses"},
        .headers = {"windows.h", "psapi.h"}
    },

    // === MAPPED FILE INFORMATION ===

    api_info{
        .name = "GetMappedFileNameW",
        .module = "psapi.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpv", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
             {.name = "lpFilename",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve name of file backing memory-mapped region",
        .security_notes = {"memory mapping analysis", "code injection detection"},
        .related_apis = {"VirtualQueryEx", "QueryWorkingSetEx"},
        .headers = {"windows.h", "psapi.h"}
    }
};

#undef WINDOWS_API_CONVENTION

} // namespace w1::abi::apis::windows