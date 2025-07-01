#pragma once

#include <string>
#include <windows.h>

// find the process ID of a given process name
// returns 0 if the process is not found
DWORD find_pid_by_name(const std::wstring& process_name);

// get the thread ID of the first thread in a given process
// returns 0 if no thread is found
DWORD get_thread_id(DWORD pid);

// set the SeDebugPrivilege for the current process
// returns TRUE if successful, FALSE otherwise
BOOL set_se_debug_privilege();