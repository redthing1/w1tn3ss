#include <windows.h>
#include <TlHelp32.h>
#include <sstream>
#include "inject.hpp"
#include "util.hpp"

DWORD find_pid_by_name(const std::wstring& process_name) {
  log_msg("searching for process ID by name");

  HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to create process snapshot. Error code: " << error;
    log_msg(ss.str());
    return 0;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (!Process32First(h_snapshot, &pe32)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to get first process. Error code: " << error;
    log_msg(ss.str());
    CloseHandle(h_snapshot);
    return 0;
  }

  DWORD pid = 0;
  do {
    if (_wcsicmp((wchar_t*) pe32.szExeFile, process_name.c_str()) == 0) {
      pid = pe32.th32ProcessID;
      break;
    }
  } while (Process32Next(h_snapshot, &pe32));

  CloseHandle(h_snapshot);

  if (pid != 0) {
    std::stringstream ss;
    ss << "process ID found: " << pid;
    log_msg(ss.str());
  } else {
    log_msg("process not found");
  }

  return pid;
}

DWORD get_thread_id(DWORD pid) {
  log_msg("searching for thread ID");

  HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to create thread snapshot. Error code: " << error;
    log_msg(ss.str());
    return 0;
  }

  THREADENTRY32 te32;
  te32.dwSize = sizeof(THREADENTRY32);

  if (!Thread32First(h_snapshot, &te32)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to get first thread. Error code: " << error;
    log_msg(ss.str());
    CloseHandle(h_snapshot);
    return 0;
  }

  DWORD thread_id = 0;
  do {
    if (te32.th32OwnerProcessID == pid) {
      HANDLE h_thread = OpenThread(READ_CONTROL, FALSE, te32.th32ThreadID);
      if (h_thread == NULL) {
        DWORD error = GetLastError();
        std::stringstream ss;
        ss << "Failed to open thread. Error code: " << error;
        log_msg(ss.str());
      } else {
        thread_id = te32.th32ThreadID;
        CloseHandle(h_thread);
        break;
      }
    }
  } while (Thread32Next(h_snapshot, &te32));

  CloseHandle(h_snapshot);

  if (thread_id != 0) {
    std::stringstream ss;
    ss << "thread ID found: " << thread_id;
    log_msg(ss.str());
  } else {
    log_msg("thread not found");
  }

  return thread_id;
}

BOOL set_se_debug_privilege() {
  log_msg("attempting to set SeDebugPrivilege");

  HANDLE h_token = NULL;
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to open process token. Error code: " << error;
    log_msg(ss.str());
    return FALSE;
  }

  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to lookup privilege value. Error code: " << error;
    log_msg(ss.str());
    CloseHandle(h_token);
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to adjust token privileges. Error code: " << error;
    log_msg(ss.str());
    CloseHandle(h_token);
    return FALSE;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    log_msg("warning: the token does not have the specified privilege");
    CloseHandle(h_token);
    return FALSE;
  }

  log_msg("SeDebugPrivilege enabled successfully");
  CloseHandle(h_token);
  return TRUE;
}
