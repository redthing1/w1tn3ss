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
    },

    // === PHASE 1: MEMORY MANIPULATION & PROCESS INJECTION ===
    
    // process memory manipulation
    api_info{
        .name = "WriteProcessMemory",
        .module = "kernel32.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBaseAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesWritten", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "write data to process memory",
        .security_notes = {"code injection vector", "requires process_vm_write access", "common malware technique"},
        .related_apis = {"ReadProcessMemory", "VirtualAllocEx", "CreateRemoteThread"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    api_info{
        .name = "ReadProcessMemory",
        .module = "kernel32.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBaseAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesRead", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "read data from process memory",
        .security_notes = {"memory dumping capability", "requires process_vm_read access"},
        .related_apis = {"WriteProcessMemory", "VirtualQueryEx"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    api_info{
        .name = "VirtualAllocEx",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flAllocationType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "flProtect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "baseAddress", .param_type = param_info::type::POINTER},
        .description = "allocate memory in remote process",
        .cleanup_api = "VirtualFreeEx",
        .security_notes = {"code injection preparation", "common dll injection technique"},
        .related_apis = {"WriteProcessMemory", "CreateRemoteThread", "VirtualFreeEx"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    api_info{
        .name = "VirtualFreeEx",
        .module = "kernel32.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "dwFreeType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "free memory in remote process",
        .related_apis = {"VirtualAllocEx", "WriteProcessMemory"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    api_info{
        .name = "VirtualProtectEx",
        .module = "kernel32.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flNewProtect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpflOldProtect", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "change protection of remote process memory",
        .security_notes = {"code execution preparation", "common shellcode injection technique"},
        .related_apis = {"VirtualProtect", "WriteProcessMemory", "VirtualAllocEx"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    api_info{
        .name = "VirtualQueryEx",
        .module = "kernel32.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "dwLength", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytesReturned", .param_type = param_info::type::SIZE},
        .description = "get information about remote process memory",
        .related_apis = {"VirtualQuery", "ReadProcessMemory"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    // thread injection
    api_info{
        .name = "CreateRemoteThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpThreadAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwStackSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpStartAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpParameter", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwCreationFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpThreadId", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "threadHandle", .param_type = param_info::type::HANDLE},
        .description = "create thread in remote process",
        .cleanup_api = "CloseHandle",
        .security_notes = {"primary dll injection method", "requires create_thread access", "common malware technique"},
        .related_apis = {"WriteProcessMemory", "VirtualAllocEx", "LoadLibraryW"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "QueueUserAPC",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::ASYNC),
        .parameters = {
            {.name = "pfnAPC", .param_type = param_info::type::CALLBACK, .param_direction = param_info::direction::IN},
            {.name = "hThread", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwData", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "queue asynchronous procedure call to thread",
        .security_notes = {"apc injection technique", "executed when thread enters alertable state"},
        .related_apis = {"OpenThread", "SleepEx", "WaitForSingleObjectEx"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    // === SYNCHRONIZATION PRIMITIVES ===

    // mutexes
    api_info{
        .name = "CreateMutexW",
        .module = "kernel32.dll",
        .api_category = api_info::category::MUTEX,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "lpMutexAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "bInitialOwner", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "mutexHandle", .param_type = param_info::type::HANDLE},
        .description = "create named or unnamed mutex object",
        .cleanup_api = "CloseHandle",
        .related_apis = {"OpenMutexW", "ReleaseMutex", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "OpenMutexW",
        .module = "kernel32.dll",
        .api_category = api_info::category::MUTEX,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "mutexHandle", .param_type = param_info::type::HANDLE},
        .description = "open existing named mutex",
        .cleanup_api = "CloseHandle",
        .related_apis = {"CreateMutexW", "ReleaseMutex"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "ReleaseMutex",
        .module = "kernel32.dll",
        .api_category = api_info::category::MUTEX,
        .flags = 0,
        .parameters = {
            {.name = "hMutex", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "release ownership of mutex",
        .related_apis = {"CreateMutexW", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    // events
    api_info{
        .name = "CreateEventW",
        .module = "kernel32.dll",
        .api_category = api_info::category::EVENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "lpEventAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "bManualReset", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "bInitialState", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "eventHandle", .param_type = param_info::type::HANDLE},
        .description = "create named or unnamed event object",
        .cleanup_api = "CloseHandle",
        .related_apis = {"OpenEventW", "SetEvent", "ResetEvent"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "OpenEventW",
        .module = "kernel32.dll",
        .api_category = api_info::category::EVENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "eventHandle", .param_type = param_info::type::HANDLE},
        .description = "open existing named event",
        .cleanup_api = "CloseHandle",
        .related_apis = {"CreateEventW", "SetEvent", "ResetEvent"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "SetEvent",
        .module = "kernel32.dll",
        .api_category = api_info::category::EVENT,
        .flags = 0,
        .parameters = {
            {.name = "hEvent", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "set event object to signaled state",
        .related_apis = {"CreateEventW", "ResetEvent", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "ResetEvent",
        .module = "kernel32.dll",
        .api_category = api_info::category::EVENT,
        .flags = 0,
        .parameters = {
            {.name = "hEvent", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "reset event object to non-signaled state",
        .related_apis = {"CreateEventW", "SetEvent", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    // semaphores
    api_info{
        .name = "CreateSemaphoreW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SEMAPHORE,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "lpSemaphoreAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lInitialCount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lMaximumCount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "semaphoreHandle", .param_type = param_info::type::HANDLE},
        .description = "create named or unnamed semaphore object",
        .cleanup_api = "CloseHandle",
        .related_apis = {"OpenSemaphoreW", "ReleaseSemaphore", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "OpenSemaphoreW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SEMAPHORE,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "semaphoreHandle", .param_type = param_info::type::HANDLE},
        .description = "open existing named semaphore",
        .cleanup_api = "CloseHandle",
        .related_apis = {"CreateSemaphoreW", "ReleaseSemaphore"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "ReleaseSemaphore",
        .module = "kernel32.dll",
        .api_category = api_info::category::SEMAPHORE,
        .flags = 0,
        .parameters = {
            {.name = "hSemaphore", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lReleaseCount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpPreviousCount", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "increase semaphore count",
        .related_apis = {"CreateSemaphoreW", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    // wait functions
    api_info{
        .name = "WaitForSingleObject",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "hHandle", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwMilliseconds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "waitResult", .param_type = param_info::type::INTEGER},
        .description = "wait for object to become signaled",
        .related_apis = {"WaitForMultipleObjects", "WaitForSingleObjectEx"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "WaitForMultipleObjects",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYNCHRONIZATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "nCount", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
            {.name = "lpHandles", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "bWaitAll", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "dwMilliseconds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "waitResult", .param_type = param_info::type::INTEGER},
        .description = "wait for multiple objects to become signaled",
        .related_apis = {"WaitForSingleObject", "WaitForMultipleObjectsEx"},
        .headers = {"windows.h", "synchapi.h"}
    },

    // === IPC - NAMED PIPES ===
    
    api_info{
        .name = "CreateNamedPipeW",
        .module = "kernel32.dll",
        .api_category = api_info::category::PIPE,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "dwOpenMode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "dwPipeMode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "nMaxInstances", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "nOutBufferSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "nInBufferSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "nDefaultTimeOut", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpSecurityAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "pipeHandle", .param_type = param_info::type::HANDLE},
        .description = "create named pipe server",
        .cleanup_api = "CloseHandle",
        .security_notes = {"ipc communication vector", "can be used for privilege escalation"},
        .related_apis = {"ConnectNamedPipe", "CreateFileW", "ReadFile", "WriteFile"},
        .headers = {"windows.h", "namedpipeapi.h"}
    },

    api_info{
        .name = "ConnectNamedPipe",
        .module = "kernel32.dll",
        .api_category = api_info::category::PIPE,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "hNamedPipe", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "wait for client to connect to named pipe",
        .related_apis = {"CreateNamedPipeW", "DisconnectNamedPipe", "PeekNamedPipe"},
        .headers = {"windows.h", "namedpipeapi.h"}
    },

    api_info{
        .name = "DisconnectNamedPipe",
        .module = "kernel32.dll",
        .api_category = api_info::category::PIPE,
        .flags = 0,
        .parameters = {
            {.name = "hNamedPipe", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "disconnect client from named pipe",
        .related_apis = {"ConnectNamedPipe", "CreateNamedPipeW"},
        .headers = {"windows.h", "namedpipeapi.h"}
    },

    api_info{
        .name = "PeekNamedPipe",
        .module = "kernel32.dll",
        .api_category = api_info::category::PIPE,
        .flags = 0,
        .parameters = {
            {.name = "hNamedPipe", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nBufferSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpBytesRead", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpTotalBytesAvail", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpBytesLeftThisMessage", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "peek at data in named pipe without removing it",
        .related_apis = {"ReadFile", "WriteFile", "ConnectNamedPipe"},
        .headers = {"windows.h", "namedpipeapi.h"}
    },

    // === IPC - MAILSLOTS ===
    
    api_info{
        .name = "CreateMailslotW",
        .module = "kernel32.dll",
        .api_category = api_info::category::IPC,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "nMaxMessageSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lReadTimeout", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpSecurityAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "mailslotHandle", .param_type = param_info::type::HANDLE},
        .description = "create mailslot for one-way ipc",
        .cleanup_api = "CloseHandle",
        .related_apis = {"GetMailslotInfo", "ReadFile", "WriteFile"},
        .headers = {"windows.h", "winbase.h"}
    },

    api_info{
        .name = "GetMailslotInfo",
        .module = "kernel32.dll",
        .api_category = api_info::category::IPC,
        .flags = 0,
        .parameters = {
            {.name = "hMailslot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpMaxMessageSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpNextSize", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpMessageCount", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpReadTimeout", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "get mailslot information",
        .related_apis = {"CreateMailslotW", "SetMailslotInfo"},
        .headers = {"windows.h", "winbase.h"}
    },

    // === SHARED MEMORY ===

    api_info{
        .name = "OpenFileMappingW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SHARED_MEMORY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "mappingHandle", .param_type = param_info::type::HANDLE},
        .description = "open existing named file mapping object",
        .cleanup_api = "CloseHandle",
        .related_apis = {"CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile"},
        .headers = {"windows.h", "memoryapi.h"}
    },

    // === PHASE 3: FILE SYSTEM & PROCESS ANALYSIS ===

    // file system operations  
    api_info{
        .name = "GetFileAttributesW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "attributes", .param_type = param_info::type::FLAGS},
        .description = "retrieve file system attributes of file or directory",
        .related_apis = {"SetFileAttributesW", "GetFileAttributesExW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "SetFileAttributesW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "dwFileAttributes", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "set attributes for file or directory",
        .security_notes = {"file hiding capability", "timestamp manipulation preparation"},
        .related_apis = {"GetFileAttributesW", "SetFileTime"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "GetFileTime",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "hFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpCreationTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpLastAccessTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpLastWriteTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve file time stamps",
        .related_apis = {"SetFileTime", "GetFileAttributesExW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "SetFileTime",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "hFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpCreationTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpLastAccessTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpLastWriteTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "set file time stamps",
        .security_notes = {"timestamp manipulation", "anti-forensics technique", "file timestomping"},
        .related_apis = {"GetFileTime", "SetFileAttributesW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "FindFirstFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "lpFindFileData", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "searchHandle", .param_type = param_info::type::HANDLE},
        .description = "search directory for file or subdirectory",
        .cleanup_api = "FindClose",
        .security_notes = {"directory enumeration capability", "file discovery"},
        .related_apis = {"FindNextFileW", "FindClose", "FindFirstFileExW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "FindNextFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "hFindFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpFindFileData", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "continue file search from previous call",
        .related_apis = {"FindFirstFileW", "FindClose"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "FindClose",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "hFindFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "close file search handle",
        .related_apis = {"FindFirstFileW", "FindNextFileW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "CreateDirectoryW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpPathName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "lpSecurityAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "create new directory",
        .security_notes = {"directory creation for persistence", "file system modification"},
        .related_apis = {"RemoveDirectoryW", "CreateDirectoryExW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "RemoveDirectoryW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpPathName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "delete existing empty directory",
        .security_notes = {"directory cleanup", "anti-forensics technique"},
        .related_apis = {"CreateDirectoryW", "DeleteFileW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "DeleteFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "lpFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "delete existing file",
        .security_notes = {"file deletion capability", "evidence destruction", "anti-forensics"},
        .related_apis = {"CreateFileW", "MoveFileW", "RemoveDirectoryW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "MoveFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpExistingFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "lpNewFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "move or rename file or directory",
        .related_apis = {"CopyFileW", "MoveFileExW", "DeleteFileW"},
        .headers = {"windows.h", "winbase.h"}
    },

    api_info{
        .name = "CopyFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpExistingFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "lpNewFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "bFailIfExists", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "copy existing file to new file",
        .security_notes = {"file duplication capability", "backup creation"},
        .related_apis = {"MoveFileW", "CopyFileExW"},
        .headers = {"windows.h", "winbase.h"}
    },

    // volume and drive information
    api_info{
        .name = "GetVolumeInformationW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpRootPathName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "lpVolumeNameBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nVolumeNameSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpVolumeSerialNumber", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpMaximumComponentLength", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpFileSystemFlags", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpFileSystemNameBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nFileSystemNameSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve volume information",
        .related_apis = {"GetDiskFreeSpaceW", "GetLogicalDrives"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "GetDiskFreeSpaceW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpRootPathName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "lpSectorsPerCluster", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpBytesPerSector", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpNumberOfFreeClusters", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpTotalNumberOfClusters", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve disk space information",
        .related_apis = {"GetVolumeInformationW", "GetDiskFreeSpaceExW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "GetLogicalDrives",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "drivesBitmask", .param_type = param_info::type::FLAGS},
        .description = "retrieve bitmask of logical drives",
        .related_apis = {"GetLogicalDriveStringsW", "GetDriveTypeW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "GetDriveTypeW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpRootPathName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "driveType", .param_type = param_info::type::INTEGER},
        .description = "determine drive type",
        .related_apis = {"GetLogicalDrives", "GetVolumeInformationW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    // === TOOLHELP32 SNAPSHOTS ===

    api_info{
        .name = "CreateToolhelp32Snapshot",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "th32ProcessID", .param_type = param_info::type::PROCESS_ID, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "snapshotHandle", .param_type = param_info::type::HANDLE},
        .description = "take snapshot of processes, threads, modules, and heaps",
        .cleanup_api = "CloseHandle",
        .security_notes = {"system enumeration capability", "process discovery", "malware analysis tool"},
        .related_apis = {"Process32FirstW", "Thread32First", "Module32FirstW"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    api_info{
        .name = "Process32FirstW",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = 0,
        .parameters = {
            {.name = "hSnapshot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lppe", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve first process from snapshot",
        .security_notes = {"process enumeration", "system discovery"},
        .related_apis = {"CreateToolhelp32Snapshot", "Process32NextW"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    api_info{
        .name = "Process32NextW",
        .module = "kernel32.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = 0,
        .parameters = {
            {.name = "hSnapshot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lppe", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve next process from snapshot",
        .related_apis = {"Process32FirstW", "CreateToolhelp32Snapshot"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    api_info{
        .name = "Thread32First",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = 0,
        .parameters = {
            {.name = "hSnapshot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpte", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve first thread from snapshot",
        .security_notes = {"thread enumeration", "injection target discovery"},
        .related_apis = {"CreateToolhelp32Snapshot", "Thread32Next", "OpenThread"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    api_info{
        .name = "Thread32Next",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = 0,
        .parameters = {
            {.name = "hSnapshot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpte", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve next thread from snapshot",
        .related_apis = {"Thread32First", "CreateToolhelp32Snapshot"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    api_info{
        .name = "Module32FirstW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .parameters = {
            {.name = "hSnapshot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpme", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve first module from snapshot",
        .security_notes = {"module enumeration", "dll discovery"},
        .related_apis = {"CreateToolhelp32Snapshot", "Module32NextW"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    api_info{
        .name = "Module32NextW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LIBRARY_LOADING,
        .flags = 0,
        .parameters = {
            {.name = "hSnapshot", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpme", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve next module from snapshot",
        .related_apis = {"Module32FirstW", "CreateToolhelp32Snapshot"},
        .headers = {"windows.h", "tlhelp32.h"}
    },

    // additional thread operations
    api_info{
        .name = "OpenThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "bInheritHandle", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN},
            {.name = "dwThreadId", .param_type = param_info::type::THREAD_ID, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "threadHandle", .param_type = param_info::type::HANDLE},
        .description = "open existing thread object",
        .cleanup_api = "CloseHandle",
        .security_notes = {"thread access for injection", "apc injection preparation"},
        .related_apis = {"GetCurrentThread", "CreateThread", "QueueUserAPC"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "SuspendThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hThread", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "previousSuspendCount", .param_type = param_info::type::INTEGER},
        .description = "suspend specified thread",
        .security_notes = {"thread suspension for analysis", "process hollowing technique"},
        .related_apis = {"ResumeThread", "OpenThread", "GetThreadContext"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "ResumeThread",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hThread", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "previousSuspendCount", .param_type = param_info::type::INTEGER},
        .description = "resume suspended thread",
        .related_apis = {"SuspendThread", "CreateThread"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "GetThreadContext",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "hThread", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpContext", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve thread context (registers)",
        .security_notes = {"register inspection", "process hollowing analysis"},
        .related_apis = {"SetThreadContext", "SuspendThread", "OpenThread"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    api_info{
        .name = "SetThreadContext",
        .module = "kernel32.dll",
        .api_category = api_info::category::THREAD_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hThread", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpContext", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "set thread context (registers)",
        .security_notes = {"execution redirection", "process hollowing technique", "injection method"},
        .related_apis = {"GetThreadContext", "SuspendThread", "ResumeThread"},
        .headers = {"windows.h", "processthreadsapi.h"}
    },

    // === PHASE 4: ANTI-ANALYSIS & EVASION DETECTION ===

    // timing and delay functions for sandbox detection
    api_info{
        .name = "GetTickCount",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "milliseconds", .param_type = param_info::type::INTEGER},
        .description = "retrieve milliseconds since system start",
        .security_notes = {"timing analysis for sandbox detection", "execution delay measurement"},
        .related_apis = {"GetTickCount64", "QueryPerformanceCounter", "timeGetTime"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    api_info{
        .name = "GetTickCount64",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "milliseconds", .param_type = param_info::type::INTEGER},
        .description = "retrieve 64-bit milliseconds since system start",
        .security_notes = {"high-resolution timing for evasion", "sandbox detection technique"},
        .related_apis = {"GetTickCount", "QueryPerformanceCounter"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    api_info{
        .name = "QueryPerformanceCounter",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .parameters = {
            {.name = "lpPerformanceCount", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve high-resolution performance counter",
        .security_notes = {"precise timing for anti-debugging", "rdtsc alternative"},
        .related_apis = {"QueryPerformanceFrequency", "GetTickCount64"},
        .headers = {"windows.h", "profileapi.h"}
    },

    api_info{
        .name = "QueryPerformanceFrequency",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .parameters = {
            {.name = "lpFrequency", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve performance counter frequency",
        .related_apis = {"QueryPerformanceCounter"},
        .headers = {"windows.h", "profileapi.h"}
    },

    api_info{
        .name = "Sleep",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "dwMilliseconds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "suspend execution for specified interval",
        .security_notes = {"delay execution for analysis evasion", "sandbox timeout technique"},
        .related_apis = {"SleepEx", "WaitForSingleObject"},
        .headers = {"windows.h", "synchapi.h"}
    },

    api_info{
        .name = "SleepEx",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "dwMilliseconds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "bAlertable", .param_type = param_info::type::BOOLEAN, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "suspend execution with alertable state",
        .security_notes = {"apc-aware sleep for evasion", "alertable delay technique"},
        .related_apis = {"Sleep", "QueueUserAPC", "WaitForSingleObjectEx"},
        .headers = {"windows.h", "synchapi.h"}
    },

    // debugging detection functions
    api_info{
        .name = "IsDebuggerPresent",
        .module = "kernel32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {},
        .return_value = {.name = "debuggerPresent", .param_type = param_info::type::BOOLEAN},
        .description = "determine if user-mode debugger is present",
        .security_notes = {"anti-debugging check", "malware evasion technique"},
        .related_apis = {"CheckRemoteDebuggerPresent", "OutputDebugStringW"},
        .headers = {"windows.h", "debugapi.h"}
    },

    api_info{
        .name = "CheckRemoteDebuggerPresent",
        .module = "kernel32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "pbDebuggerPresent", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "determine if debugger is attached to process",
        .security_notes = {"remote debugging detection", "anti-analysis technique"},
        .related_apis = {"IsDebuggerPresent", "OpenProcess"},
        .headers = {"windows.h", "debugapi.h"}
    },

    api_info{
        .name = "OutputDebugStringW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = 0,
        .parameters = {
            {.name = "lpOutputString", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "send string to debugger for display",
        .security_notes = {"debugger detection via exception", "anti-debugging technique"},
        .related_apis = {"IsDebuggerPresent", "SetLastError"},
        .headers = {"windows.h", "debugapi.h"}
    },

    // system information for vm/sandbox detection
    api_info{
        .name = "GetUserNameW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "pcbBuffer", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve current user name",
        .security_notes = {"user profiling for sandbox detection", "common sandbox usernames"},
        .related_apis = {"GetComputerNameW", "GetEnvironmentVariableW"},
        .headers = {"windows.h", "winbase.h"}
    },

    api_info{
        .name = "GetEnvironmentVariableW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve environment variable value",
        .security_notes = {"environment fingerprinting", "sandbox detection via env vars"},
        .related_apis = {"SetEnvironmentVariableW", "GetEnvironmentStringsW"},
        .headers = {"windows.h", "processenv.h"}
    },

    api_info{
        .name = "SetEnvironmentVariableW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpValue", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "set environment variable value",
        .related_apis = {"GetEnvironmentVariableW"},
        .headers = {"windows.h", "processenv.h"}
    },

    api_info{
        .name = "GetCommandLineW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "commandLine", .param_type = param_info::type::STRING},
        .description = "retrieve command line string for current process",
        .security_notes = {"argument analysis for detection", "execution context fingerprinting"},
        .related_apis = {"GetEnvironmentVariableW", "GetModuleFileNameW"},
        .headers = {"windows.h", "processenv.h"}
    },

    api_info{
        .name = "GetVersionExW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::DEPRECATED),
        .parameters = {
            {.name = "lpVersionInformation", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve operating system version information",
        .security_notes = {"os fingerprinting for evasion", "version-specific exploits"},
        .related_apis = {"GetSystemInfo", "RtlGetVersion"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    api_info{
        .name = "GetNativeSystemInfo",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "lpSystemInfo", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "retrieve native system information",
        .security_notes = {"architecture detection", "wow64 environment analysis"},
        .related_apis = {"GetSystemInfo", "IsWow64Process"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    api_info{
        .name = "IsWow64Process",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "hProcess", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "Wow64Process", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "determine if process is running under wow64",
        .security_notes = {"architecture detection", "32-bit on 64-bit detection"},
        .related_apis = {"GetNativeSystemInfo", "GetSystemInfo"},
        .headers = {"windows.h", "wow64apiset.h"}
    },

    // locale and region detection
    api_info{
        .name = "GetLocaleInfoW",
        .module = "kernel32.dll",
        .api_category = api_info::category::LOCALE,
        .flags = 0,
        .parameters = {
            {.name = "Locale", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "LCType", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpLCData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "cchData", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::INTEGER},
        .description = "retrieve locale-specific information",
        .security_notes = {"geographic targeting", "locale-based evasion"},
        .related_apis = {"GetSystemDefaultLCID", "GetUserDefaultLCID"},
        .headers = {"windows.h", "winnls.h"}
    },

    api_info{
        .name = "GetSystemDefaultLCID",
        .module = "kernel32.dll",
        .api_category = api_info::category::LOCALE,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "lcid", .param_type = param_info::type::INTEGER},
        .description = "retrieve system default locale identifier",
        .security_notes = {"system locale fingerprinting", "regional targeting"},
        .related_apis = {"GetLocaleInfoW", "GetUserDefaultLCID"},
        .headers = {"windows.h", "winnls.h"}
    },

    api_info{
        .name = "GetTimeZoneInformation",
        .module = "kernel32.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .parameters = {
            {.name = "lpTimeZoneInformation", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "retrieve current time zone settings",
        .security_notes = {"geographic location inference", "timezone-based targeting"},
        .related_apis = {"GetSystemTime", "GetLocalTime"},
        .headers = {"windows.h", "timezoneapi.h"}
    },

    // cpu information for vm detection
    api_info{
        .name = "GetLogicalProcessorInformation",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "Buffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "ReturnedLength", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve logical processor and cache information",
        .security_notes = {"cpu core detection for vm analysis", "hardware fingerprinting"},
        .related_apis = {"GetSystemInfo", "GetLogicalProcessorInformationEx"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    // memory status for vm detection
    api_info{
        .name = "GlobalMemoryStatusEx",
        .module = "kernel32.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .parameters = {
            {.name = "lpBuffer", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve extended memory status",
        .security_notes = {"memory size detection for vm analysis", "low memory sandbox detection"},
        .related_apis = {"GetSystemInfo", "VirtualQuery"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    // file system detection
    api_info{
        .name = "GetTempPathW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "nBufferLength", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve temporary file path",
        .security_notes = {"temp directory analysis", "sandbox temp path detection"},
        .related_apis = {"GetWindowsDirectoryW", "GetSystemDirectoryW"},
        .headers = {"windows.h", "fileapi.h"}
    },

    api_info{
        .name = "GetWindowsDirectoryW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "uSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve windows directory path",
        .security_notes = {"system directory analysis", "installation path detection"},
        .related_apis = {"GetSystemDirectoryW", "GetTempPathW"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    api_info{
        .name = "GetSystemDirectoryW",
        .module = "kernel32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpBuffer", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "uSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "retrieve system directory path",
        .related_apis = {"GetWindowsDirectoryW", "GetSystemWow64DirectoryW"},
        .headers = {"windows.h", "sysinfoapi.h"}
    },

    // === REGISTRY MANIPULATION APIs ===

    api_info{
        .name = "RegOpenKeyExW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpSubKey", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "ulOptions", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "samDesired", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "phkResult", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "open registry key",
        .cleanup_api = "RegCloseKey",
        .security_notes = {"registry access", "system configuration modification"},
        .related_apis = {"RegCreateKeyExW", "RegCloseKey", "RegQueryValueExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegCreateKeyExW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpSubKey", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "Reserved", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpClass", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "dwOptions", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "samDesired", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpSecurityAttributes", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "phkResult", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpdwDisposition", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "create or open registry key",
        .cleanup_api = "RegCloseKey",
        .security_notes = {"registry modification", "persistence mechanism", "system configuration change"},
        .related_apis = {"RegOpenKeyExW", "RegSetValueExW", "RegDeleteKeyW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegSetValueExW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpValueName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "Reserved", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "dwType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "cbData", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "set registry value",
        .security_notes = {"registry modification", "persistence mechanism", "autostart configuration"},
        .related_apis = {"RegQueryValueExW", "RegDeleteValueW", "RegCreateKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegQueryValueExW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpValueName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpReserved", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpType", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "lpcbData", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "query registry value",
        .security_notes = {"registry inspection", "system configuration analysis"},
        .related_apis = {"RegSetValueExW", "RegEnumValueW", "RegOpenKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegDeleteKeyW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpSubKey", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "delete registry key",
        .security_notes = {"registry cleanup", "evidence removal", "system modification"},
        .related_apis = {"RegCreateKeyExW", "RegDeleteValueW", "RegDeleteTreeW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegDeleteValueW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpValueName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "delete registry value",
        .security_notes = {"registry cleanup", "configuration removal"},
        .related_apis = {"RegSetValueExW", "RegDeleteKeyW", "RegQueryValueExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegCloseKey",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "close registry key handle",
        .related_apis = {"RegOpenKeyExW", "RegCreateKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegEnumKeyExW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwIndex", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpName", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "lpcchName", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "lpReserved", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpClass", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "lpcchClass", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "lpftLastWriteTime", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "enumerate registry subkeys",
        .security_notes = {"registry discovery", "system configuration enumeration"},
        .related_apis = {"RegEnumValueW", "RegOpenKeyExW", "RegQueryInfoKeyW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegEnumValueW",
        .module = "kernel32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .parameters = {
            {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "dwIndex", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpValueName", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "lpcchValueName", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "lpReserved", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpType", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "lpcbData", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "status", .param_type = param_info::type::INTEGER},
        .description = "enumerate registry values",
        .security_notes = {"registry discovery", "value enumeration"},
        .related_apis = {"RegEnumKeyExW", "RegQueryValueExW", "RegOpenKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    }
};

} // namespace w1::abi::apis::windows