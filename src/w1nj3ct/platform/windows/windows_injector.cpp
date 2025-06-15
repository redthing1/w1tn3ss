#include "windows_injector.hpp"
#include "../../error.hpp"

// include windows injection backend
#include "../../backend/windows/auxiliary.hpp"
#include "../../backend/windows/inject.hpp"

#include <windows.h>

#include <psapi.h>
#include <string>
#include <tlhelp32.h>

namespace w1::inject::windows {

// helper to convert string to wstring
std::wstring string_to_wstring(const std::string& str) {
  if (str.empty()) {
    return std::wstring();
  }
  int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
  std::wstring result(size - 1, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
  return result;
}

// helper to convert wstring to string
std::string wstring_to_string(const std::wstring& wstr) {
  if (wstr.empty()) {
    return std::string();
  }
  int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
  std::string result(size - 1, 0);
  WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
  return result;
}

result inject_runtime(const config& cfg) {
  // validate we have a target
  if (!cfg.pid && !cfg.process_name) {
    return make_error_result(error_code::configuration_invalid, "no target specified");
  }

  DWORD target_pid = 0;

  // resolve process name to pid if needed
  if (cfg.process_name) {
    auto processes = find_processes_by_name(*cfg.process_name);
    if (processes.empty()) {
      return make_error_result(error_code::target_not_found, *cfg.process_name);
    }
    if (processes.size() > 1) {
      return make_error_result(error_code::multiple_targets_found, *cfg.process_name);
    }
    target_pid = processes[0].pid;
  } else {
    target_pid = *cfg.pid;
  }

  // open process handle
  HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
  if (h_process == NULL) {
    DWORD err = GetLastError();
    return make_error_result(translate_platform_error(static_cast<int>(err)), "failed to open process", err);
  }

  // convert library path to wide string
  std::wstring dll_path = string_to_wstring(cfg.library_path);

  // choose injection technique and inject
  BOOL success = FALSE;
  switch (cfg.windows_technique) {
  case windows_technique::create_remote_thread:
    success = inject_dll_create_remote_thread(h_process, dll_path);
    break;
  case windows_technique::set_windows_hook:
    success = inject_dll_set_windows_hook_ex(h_process, target_pid, dll_path);
    break;
  case windows_technique::rtl_create_user_thread:
    success = inject_dll_rtl_create_user_thread(h_process, dll_path);
    break;
  case windows_technique::reflective_loader:
    success = inject_dll_reflective_loader(h_process, dll_path);
    break;
  default:
    CloseHandle(h_process);
    return make_error_result(error_code::technique_not_supported, "unknown windows technique");
  }

  CloseHandle(h_process);

  if (!success) {
    DWORD err = GetLastError();
    return make_error_result(translate_platform_error(static_cast<int>(err)), "injection failed", err);
  }

  return make_success_result(target_pid);
}

result inject_preload(const config& cfg) {
  // Windows launch injection using suspended process approach

  // validate we have a binary path for launch injection
  if (!cfg.binary_path) {
    return make_error_result(error_code::configuration_invalid, "binary_path required for launch injection");
  }

  // convert paths to wide strings
  std::wstring binary_path = string_to_wstring(*cfg.binary_path);
  std::wstring dll_path = string_to_wstring(cfg.library_path);

  // perform launch injection
  DWORD target_pid = 0;
  BOOL success = inject_dll_launch_suspended(binary_path, dll_path, cfg.args, &target_pid);

  if (!success) {
    DWORD err = GetLastError();
    return make_error_result(translate_platform_error(static_cast<int>(err)), "launch injection failed", err);
  }

  return make_success_result(target_pid);
}

std::vector<process_info> list_processes() {
  std::vector<process_info> processes;

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return processes;
  }

  PROCESSENTRY32W pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32W);

  if (Process32FirstW(snapshot, &pe32)) {
    do {
      process_info info;
      info.pid = pe32.th32ProcessID;
      info.name = wstring_to_string(pe32.szExeFile);

      // get full path
      HANDLE h_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
      if (h_process != NULL) {
        wchar_t path[MAX_PATH];
        DWORD path_len = MAX_PATH;
        if (QueryFullProcessImageNameW(h_process, 0, path, &path_len)) {
          info.full_path = wstring_to_string(path);
        }
        CloseHandle(h_process);
      }

      processes.push_back(info);
    } while (Process32NextW(snapshot, &pe32));
  }

  CloseHandle(snapshot);
  return processes;
}

std::vector<process_info> find_processes_by_name(const std::string& name) {
  std::vector<process_info> matches;
  auto all_processes = list_processes();

  for (const auto& proc : all_processes) {
    if (proc.name == name) {
      matches.push_back(proc);
    }
  }

  return matches;
}

std::optional<process_info> get_process_info(int pid) {
  auto all_processes = list_processes();

  for (const auto& proc : all_processes) {
    if (proc.pid == pid) {
      return proc;
    }
  }

  return std::nullopt;
}

bool check_injection_capabilities() {
  // check if we can open a process with required permissions
  HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
  if (h_process != NULL) {
    CloseHandle(h_process);
    return true;
  }

  return false;
}

} // namespace w1::inject::windows