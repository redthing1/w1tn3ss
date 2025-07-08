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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "FileHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "DesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "ObjectAttributes",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "IoStatusBlock",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "AllocationSize",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "FileAttributes",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "ShareAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "CreateDisposition",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "CreateOptions",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "EaBuffer",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "EaLength", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native file creation",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtReadFile",
        .module = "ntdll.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "FileHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "Event", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "ApcRoutine",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "ApcContext",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "IoStatusBlock",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "Buffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
             {.name = "Length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "ByteOffset",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "Key", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native file read operation",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtWriteFile",
        .module = "ntdll.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "FileHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "Event", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "ApcRoutine",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "ApcContext",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "IoStatusBlock",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "Buffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
             {.name = "Length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "ByteOffset",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "Key", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "BaseAddress",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN_OUT},
             {.name = "ZeroBits",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "RegionSize",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN_OUT},
             {.name = "AllocationType",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "Protect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "BaseAddress",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN_OUT},
             {.name = "RegionSize",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN_OUT},
             {.name = "FreeType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "DesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "ObjectAttributes",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "ParentProcess",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "InheritObjectTable",
              .param_type = param_info::type::BOOLEAN,
              .param_direction = param_info::direction::IN},
             {.name = "SectionHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "DebugPort",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ExceptionPort",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ExitStatus",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ThreadHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "DesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "ObjectAttributes",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ClientId",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "ThreadContext",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "InitialTeb",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "CreateSuspended",
              .param_type = param_info::type::BOOLEAN,
              .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "KeyHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "DesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "ObjectAttributes",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native registry key open",
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtQueryValueKey",
        .module = "ntdll.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "KeyHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ValueName",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "KeyValueInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "KeyValueInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "Length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "ResultLength",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "Alertable",
              .param_type = param_info::type::BOOLEAN,
              .param_direction = param_info::direction::IN},
             {.name = "DelayInterval",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN}},
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
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "Handle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native handle close",
        .related_apis = {"CloseHandle"},
        .headers = {"ntddk.h"}
    },

    // === ANTI-ANALYSIS & EVASION DETECTION (NTDLL) ===

    // process information queries for debugging detection
    api_info{
        .name = "NtQueryInformationProcess",
        .module = "ntdll.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "ProcessInformationLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN},
             {.name = "ReturnLength",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "query process information including debug flags",
        .security_notes =
            {"debugging detection via process flags", "heap flags inspection", "critical anti-analysis api"},
        .related_apis = {"NtSetInformationProcess", "IsDebuggerPresent"},
        .headers = {"ntddk.h", "winternl.h"}
    },

    api_info{
        .name = "NtSetInformationProcess",
        .module = "ntdll.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessInformationLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "modify process information and debug flags",
        .security_notes = {"disable debugging", "process manipulation", "anti-analysis technique"},
        .related_apis = {"NtQueryInformationProcess"},
        .headers = {"ntddk.h", "winternl.h"}
    },

    api_info{
        .name = "NtQuerySystemInformation",
        .module = "ntdll.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "SystemInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "SystemInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "SystemInformationLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN},
             {.name = "ReturnLength",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "query system information including debug state",
        .security_notes = {"kernel debugger detection", "system configuration analysis", "vm detection"},
        .related_apis = {"NtQueryInformationProcess", "GetSystemInfo"},
        .headers = {"ntddk.h", "winternl.h"}
    },

    api_info{
        .name = "NtQuerySystemTime",
        .module = "ntdll.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "SystemTime",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "retrieve current system time",
        .security_notes = {"timing analysis for evasion", "native time access"},
        .related_apis = {"NtDelayExecution", "GetSystemTime"},
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtSetSystemTime",
        .module = "ntdll.dll",
        .api_category = api_info::category::TIME,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::PRIVILEGED),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "SystemTime",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "PreviousTime",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "modify system time",
        .security_notes = {"timestamp manipulation", "forensic timestamp evasion", "requires privilege"},
        .related_apis = {"NtQuerySystemTime", "SetSystemTime"},
        .headers = {"ntddk.h"}
    },

    // advanced heap manipulation for anti-debugging
    api_info{
        .name = "RtlGetProcessHeaps",
        .module = "ntdll.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "NumberOfHeaps",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "ProcessHeaps",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "heapCount", .param_type = param_info::type::INTEGER},
        .description = "retrieve handles to process heaps",
        .security_notes = {"heap flag analysis for debugging detection", "heap structure inspection"},
        .related_apis = {"RtlQueryHeapInformation", "GetProcessHeap"},
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "LdrGetDllHandle",
        .module = "ntdll.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "DllPath", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "DllCharacteristics",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "DllName", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
             {.name = "DllHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "get handle to loaded dll",
        .security_notes = {"detect analysis tools by checking loaded dlls", "vm/debugger dll detection"},
        .related_apis = {"LdrLoadDll", "GetModuleHandle"},
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "LdrLoadDll",
        .module = "ntdll.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "DllPath", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "DllCharacteristics",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "DllName", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
             {.name = "DllHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "load dll into process address space",
        .security_notes = {"manual dll loading", "evasion via native api"},
        .related_apis = {"LdrGetDllHandle", "LoadLibrary"},
        .headers = {"ntddk.h"}
    },

    // exception handling for anti-debugging
    api_info{
        .name = "NtSetInformationThread",
        .module = "ntdll.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ThreadHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ThreadInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "ThreadInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::IN},
             {.name = "ThreadInformationLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "modify thread information including hide from debugger",
        .security_notes = {"hide thread from debugger", "anti-debugging technique"},
        .related_apis = {"NtQueryInformationThread", "SetThreadInformation"},
        .headers = {"ntddk.h"}
    },

    api_info{
        .name = "NtQueryInformationThread",
        .module = "ntdll.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ThreadHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "ThreadInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "ThreadInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "ThreadInformationLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN},
             {.name = "ReturnLength",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "query thread information including debug flags",
        .security_notes = {"thread state analysis", "debugging detection"},
        .related_apis = {"NtSetInformationThread", "GetThreadContext"},
        .headers = {"ntddk.h"}
    }
};

#undef WINDOWS_API_CONVENTION

} // namespace w1::abi::apis::windows