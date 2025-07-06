#pragma once

#include "../../api_knowledge_db.hpp"
#include <array>

namespace w1::abi::apis::windows {

/**
 * @brief windows system api definitions
 * 
 * covers common windows apis from:
 * - kernel32.dll: process, thread, memory, file operations
 * - ntdll.dll: native nt apis
 * - user32.dll: window management, ui
 * - advapi32.dll: registry, security
 * 
 * note: windows apis typically use stdcall on x86 and microsoft convention on x64
 *       the calling convention detector will handle this automatically
 */

constexpr std::array windows_kernel32_apis = {
    // process management
    api_info{
        .name = "CreateProcessW",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CREATES_PROCESS),
        .parameters = {
            {.name = "lpApplicationName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpCommandLine", .param_type = param_info::type::STRING, .param_direction = param_info::direction::INOUT},
            {.name = "lpProcessAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpThreadAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandles", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "dwCreationFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpEnvironment", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpCurrentDirectory", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpStartupInfo", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpProcessInformation", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "create new process and primary thread",
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "VirtualAlloc",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flAllocationType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "flProtect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "baseAddress", .param_type = param_info::type::POINTER},
        .description = "allocate virtual memory",
        .cleanup_api = "VirtualFree",
        .headers = {"windows.h", "memoryapi.h"}
    },

    api_info{
        .name = "VirtualFree",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "dwFreeType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "free virtual memory",
        .headers = {"windows.h", "memoryapi.h"}
    },

    // file operations
    api_info{
        .name = "CreateFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_RESOURCE),
        .parameters = {
            {.name = "lpFileName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "dwShareMode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpSecurityAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwCreationDisposition", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "dwFlagsAndAttributes", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "hTemplateFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
        .description = "open or create file",
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "ReadFile",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::READS_DATA),
        .parameters = {
            {.name = "hFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nNumberOfBytesToRead", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesRead", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::INOUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "read from file",
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "WriteFile",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::WRITES_DATA),
        .parameters = {
            {.name = "hFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "nNumberOfBytesToWrite", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesWritten", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::INOUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "write to file",
        .headers = {"windows.h", "fileapi.h"}
    },

    // thread management
    api_info{
        .name = "CreateThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CREATES_THREAD),
        .parameters = {
            {.name = "lpThreadAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwStackSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpStartAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpParameter", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwCreationFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpThreadId", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
        .description = "create new thread",
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    // synchronization
    api_info{
        .name = "WaitForSingleObject",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKS_EXECUTION),
        .parameters = {
            {.name = "hHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwMilliseconds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "wait for object state",
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "CreateMutexW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_RESOURCE),
        .parameters = {
            {.name = "lpMutexAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "bInitialOwner", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
        .description = "create mutex object",
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "synchapi.h"}
    },

    // dll/module management
    api_info{
        .name = "LoadLibraryW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::LOADS_CODE),
        .parameters = {
            {.name = "lpLibFileName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "module", .param_type = param_info::type::POINTER},
        .description = "load dll into process",
        .cleanup_api = "FreeLibrary",
        .headers = {"windows.h", "libloaderapi.h"}
    },

    api_info{
        .name = "GetProcAddress",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .parameters = {
            {.name = "hModule", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpProcName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "address", .param_type = param_info::type::POINTER},
        .description = "get function address from dll",
        .headers = {"windows.h", "libloaderapi.h"}
    }
};

constexpr std::array windows_ntdll_apis = {
    // native nt apis
    api_info{
        .name = "NtCreateFile",
        .module = "ntdll.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_RESOURCE),
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
        .name = "NtAllocateVirtualMemory",
        .module = "ntdll.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "ProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "BaseAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::INOUT},
            {.name = "ZeroBits", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "RegionSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::INOUT},
            {.name = "AllocationType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "Protect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "native memory allocation",
        .cleanup_api = "NtFreeVirtualMemory",
        .headers = {"ntddk.h"}
    }
};

constexpr std::array windows_user32_apis = {
    // window management
    api_info{
        .name = "CreateWindowExW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_RESOURCE),
        .parameters = {
            {.name = "dwExStyle", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpClassName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpWindowName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "dwStyle", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "X", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "Y", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "nWidth", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "nHeight", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "hWndParent", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hMenu", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hInstance", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "hwnd", .param_type = param_info::type::HANDLE},
        .description = "create window",
        .cleanup_api = "DestroyWindow",
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "MessageBoxW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKS_EXECUTION),
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpText", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpCaption", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "uType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "display message box",
        .headers = {"windows.h", "winuser.h"}
    }
};

// aggregate all windows apis
inline std::vector<api_info> get_all_windows_apis() {
    std::vector<api_info> apis;
    
    // kernel32
    apis.insert(apis.end(), windows_kernel32_apis.begin(), windows_kernel32_apis.end());
    
    // ntdll
    apis.insert(apis.end(), windows_ntdll_apis.begin(), windows_ntdll_apis.end());
    
    // user32
    apis.insert(apis.end(), windows_user32_apis.begin(), windows_user32_apis.end());
    
    return apis;
}

} // namespace w1::abi::apis::windows