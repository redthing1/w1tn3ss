#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::windows {

/**
 * @brief kernel32.dll api definitions
 *
 * covers windows kernel32.dll apis for:
 * - process and thread management
 * - memory allocation and management
 * - file and i/o operations
 * - i/o completion ports
 * - synchronization primitives
 * - library/module loading
 * - error handling and system information
 * - string conversion utilities
 */

static const std::vector<api_info> windows_kernel32_apis = {
    // process management
    api_info{
        .name = "CreateProcessW",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpApplicationName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpCommandLine", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN_OUT},
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
        .name = "OpenProcess",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) | 
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "dwProcessId", .param_type = param_info::type::PROCESS_ID, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
        .description = "open existing process object",
        .cleanup_api = "CloseHandle",
        .related_apis = {"GetCurrentProcess", "CreateProcess"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "GetCurrentProcess",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
        .description = "get pseudo handle to current process",
        .related_apis = {"GetCurrentThread", "OpenProcess"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "GetCurrentThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "handle", .param_type = param_info::type::HANDLE},
        .description = "get pseudo handle to current thread",
        .related_apis = {"GetCurrentProcess", "OpenThread"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "ExitProcess",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "uExitCode", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "terminate current process and all its threads",
        .related_apis = {"TerminateProcess", "exit"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "TerminateProcess",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "uExitCode", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "terminate specified process forcefully",
        .security_notes = {"dangerous - can corrupt data", "use ExitProcess for self-termination"},
        .related_apis = {"ExitProcess", "OpenProcess"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "GetExitCodeProcess",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = 0,
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpExitCode", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve exit code of specified process",
        .related_apis = {"ExitProcess", "WaitForSingleObject"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    // memory management
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

    api_info{
        .name = "HeapAlloc",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "hHeap", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "dwBytes", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "pointer", .param_type = param_info::type::POINTER},
        .description = "allocate memory from heap",
        .cleanup_api = "HeapFree",
        .related_apis = {"GetProcessHeap", "HeapCreate"},
        .headers = {"windows.h", "heapapi.h"}
    },

    api_info{
        .name = "HeapFree",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "hHeap", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpMem", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "free memory allocated from heap",
        .related_apis = {"HeapAlloc", "GetProcessHeap"},
        .headers = {"windows.h", "heapapi.h"}
    },

    api_info{
        .name = "GetProcessHeap",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "heap", .param_type = param_info::type::HANDLE},
        .description = "get handle to default heap of calling process",
        .related_apis = {"HeapAlloc", "HeapFree", "HeapCreate"},
        .headers = {"windows.h", "heapapi.h"}
    },

    // i/o completion ports
    api_info{
        .name = "GetQueuedCompletionStatus",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING) |
                 static_cast<uint32_t>(api_info::behavior_flags::ASYNC),
        .parameters = {
            {.name = "CompletionPort", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesTransferred", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpCompletionKey", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "dwMilliseconds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "dequeue completion packet from i/o completion port",
        .related_apis = {"CreateIoCompletionPort", "PostQueuedCompletionStatus"},
        .headers = {"windows.h", "ioapiset.h"}
    },

    api_info{
        .name = "CreateIoCompletionPort",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::ASYNC),
        .parameters = {
            {.name = "FileHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "ExistingCompletionPort", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "CompletionKey", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "NumberOfConcurrentThreads", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "port", .param_type = param_info::type::HANDLE},
        .description = "create or associate file with i/o completion port",
        .cleanup_api = "CloseHandle",
        .related_apis = {"GetQueuedCompletionStatus", "PostQueuedCompletionStatus"},
        .headers = {"windows.h", "ioapiset.h"}
    },

    api_info{
        .name = "PostQueuedCompletionStatus",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ASYNC),
        .parameters = {
            {.name = "CompletionPort", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwNumberOfBytesTransferred", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "dwCompletionKey", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "post completion packet to i/o completion port",
        .related_apis = {"CreateIoCompletionPort", "GetQueuedCompletionStatus"},
        .headers = {"windows.h", "ioapiset.h"}
    },

    // file operations
    api_info{
        .name = "CreateFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
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
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "hFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nNumberOfBytesToRead", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesRead", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "read from file",
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "WriteFile",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "hFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "nNumberOfBytesToWrite", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesWritten", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "write to file",
        .headers = {"windows.h", "fileapi.h"}
    },

    // thread management
    api_info{
        .name = "CreateThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
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
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
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
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
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

    // handle management
    api_info{
        .name = "CloseHandle",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "hObject", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "close object handle",
        .security_notes = {"double-close can cause issues", "invalid handle causes undefined behavior"},
        .headers = {"windows.h", "handleapi.h"}
    },

    api_info{
        .name = "DuplicateHandle",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "hSourceProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hSourceHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hTargetProcessHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpTargetHandle", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "dwOptions", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "duplicate object handle",
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "handleapi.h"}
    },

    // error handling  
    api_info{
        .name = "GetLastError",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "retrieve calling thread's last error code",
        .related_apis = {"SetLastError", "FormatMessage"},
        .headers = {"windows.h", "errhandlingapi.h"}
    },

    api_info{
        .name = "SetLastError",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "dwErrCode", .param_type = param_info::type::ERROR_CODE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "set calling thread's last error code",
        .related_apis = {"GetLastError", "FormatMessage"},
        .headers = {"windows.h", "errhandlingapi.h"}
    },

    api_info{
        .name = "FormatMessageW",
        .module = "kernel32.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpSource", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwMessageId", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "dwLanguageId", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "Arguments", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "format message string from system error code",
        .related_apis = {"GetLastError", "SetLastError"},
        .headers = {"windows.h", "winbase.h"}
    },

    // system information
    api_info{
        .name = "GetSystemInfo",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "lpSystemInfo", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "retrieve system configuration information",
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    api_info{
        .name = "GetComputerNameW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve netbios name of local computer",
        .headers = {"windows.h", "winbase.h"}
    },

    // library/module loading
    api_info{
        .name = "LoadLibraryW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
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
    },

    api_info{
        .name = "GetModuleHandleW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .parameters = {
            {.name = "lpModuleName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "module", .param_type = param_info::type::POINTER},
        .description = "get handle to loaded module",
        .related_apis = {"LoadLibraryW", "GetModuleFileName"},
        .headers = {"windows.h", "libloaderapi.h"}
    },

    api_info{
        .name = "GetModuleFileNameW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .parameters = {
            {.name = "hModule", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpFilename", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "get fully qualified path of loaded module",
        .related_apis = {"GetModuleHandle", "LoadLibraryW"},
        .headers = {"windows.h", "libloaderapi.h"}
    },

    api_info{
        .name = "FreeLibrary",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hLibModule", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "unload dll from process",
        .related_apis = {"LoadLibraryW", "GetProcAddress"},
        .headers = {"windows.h", "libloaderapi.h"}
    },

    // string conversion utilities
    api_info{
        .name = "MultiByteToWideChar",
        .module = "kernel32.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .parameters = {
            {.name = "CodePage", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpMultiByteStr", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "cbMultiByte", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpWideCharStr", .param_type = param_info::type::WSTRING, .param_direction = param_info::direction::OUT},
            {.name = "cchWideChar", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "convert multibyte string to wide character string",
        .related_apis = {"WideCharToMultiByte"},
        .headers = {"windows.h", "stringapiset.h"}
    },

    api_info{
        .name = "WideCharToMultiByte",
        .module = "kernel32.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .parameters = {
            {.name = "CodePage", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpWideCharStr", .param_type = param_info::type::WSTRING, .param_direction = param_info::direction::IN},
            {.name = "cchWideChar", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpMultiByteStr", .param_type = param_info::type::STRING, .param_direction = param_info::direction::OUT},
            {.name = "cbMultiByte", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpDefaultChar", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpUsedDefaultChar", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "convert wide character string to multibyte string",
        .related_apis = {"MultiByteToWideChar"},
        .headers = {"windows.h", "stringapiset.h"}
    }
};

} // namespace w1::abi::apis::windows