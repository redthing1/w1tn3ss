#pragma once

#include <string>
#include <windows.h>

// Find the process ID of a given process name
// Returns 0 if the process is not found
DWORD find_pid_by_name(const std::wstring& process_name);

// Get the thread ID of the first thread in a given process
// Returns 0 if no thread is found
DWORD get_thread_id(DWORD pid);

// Set the SeDebugPrivilege for the current process
// Returns TRUE if successful, FALSE otherwise
BOOL set_se_debug_privilege();