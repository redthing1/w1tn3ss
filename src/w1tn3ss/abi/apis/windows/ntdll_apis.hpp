#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::windows {

/**
 * @brief ntdll.dll api definitions
 *
 * covers native nt api layer:
 * - native file operations
 * - native memory management 
 * - native process/thread operations
 * - native registry operations
 * - low-level system services
 *
 * note: these are undocumented internal apis that may change between windows versions
 */

static const std::vector<api_info> windows_ntdll_apis = {
    // native file operations
    api_info{
        .name = "NtCreateFile",
        .module = "ntdll.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "FileHandle", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "DesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "ObjectAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "IoStatusBlock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "AllocationSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "FileAttributes", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "ShareAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "CreateDisposition", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "CreateOptions", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "EaBuffer", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "EaLength", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native file creation",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtReadFile",
        .module = "ntdll.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "FileHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "Event", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ApcRoutine", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "ApcContext", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "IoStatusBlock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "Buffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "Length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "ByteOffset", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "Key", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native file read operation",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtWriteFile",
        .module = "ntdll.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "FileHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "Event", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ApcRoutine", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "ApcContext", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "IoStatusBlock", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "Buffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "Length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "ByteOffset", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "Key", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native file write operation",
        .headers = {"ntddk.h"}
    },

    // native memory management
    api_info{
        .name = "NtAllocateVirtualMemory",
        .module = "ntdll.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "ProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "BaseAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "ZeroBits", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "RegionSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "AllocationType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "Protect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native memory allocation",
        .cleanup_api = "NtFreeVirtualMemory",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtFreeVirtualMemory",
        .module = "ntdll.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "ProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "BaseAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "RegionSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "FreeType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native memory deallocation",
        .headers = {"ntddk.h"}
    },

    // native process operations
    api_info{
        .name = "NtCreateProcess",
        .module = "ntdll.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "ProcessHandle", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "DesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "ObjectAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "ParentProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "InheritObjectTable", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "SectionHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "DebugPort", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ExceptionPort", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native process creation",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtTerminateProcess",
        .module = "ntdll.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "ProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ExitStatus", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native process termination",
        .security_notes = {"forceful termination", "can corrupt application state"},
        .headers = {"ntddk.h"}
    },

    // native thread operations
    api_info{
        .name = "NtCreateThread",
        .module = "ntdll.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "ThreadHandle", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "DesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "ObjectAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "ProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ClientId", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "ThreadContext", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "InitialTeb", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "CreateSuspended", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native thread creation",
        .headers = {"ntddk.h"}
    },

    // native registry operations
    api_info{
        .name = "NtOpenKey",
        .module = "ntdll.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .parameters = {
            {.name = "KeyHandle", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "DesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "ObjectAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native registry key open",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtQueryValueKey",
        .module = "ntdll.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .parameters = {
            {.name = "KeyHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ValueName", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "KeyValueInformationClass", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "KeyValueInformation", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "Length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "ResultLength", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native registry value query",
        .headers = {"ntddk.h"}
    },

    // low-level system services
    api_info{
        .name = "NtDelayExecution",
        .module = "ntdll.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "Alertable", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "DelayInterval", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native thread delay/sleep",
        .related_apis = {"Sleep", "SleepEx"},
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtClose",
        .module = "ntdll.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "Handle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native handle close",
        .related_apis = {"CloseHandle"},
        .headers = {"ntddk.h"}
    }
};

} // namespace w1::abi::apis::windows