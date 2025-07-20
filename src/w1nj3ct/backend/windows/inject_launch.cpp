#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

// Windows version constants for process mitigation
#ifndef PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF
#define PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF (0x00000001ULL << 56)
#endif

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif

#include "winapis.h"
#include "inject.hpp"
#include "util.hpp"

// convert std::string to std::wstring
std::wstring string_to_wstring(const std::string& str) {
  if (str.empty()) {
    return std::wstring();
  }
  int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
  std::wstring result(size - 1, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
  return result;
}

// build command line string from binary path and arguments
std::wstring build_command_line(const std::wstring& binary_path, const std::vector<std::string>& args) {
  std::wstring cmd_line = L"\"" + binary_path + L"\"";

  for (const auto& arg : args) {
    cmd_line += L" \"" + string_to_wstring(arg) + L"\"";
  }

  return cmd_line;
}

// internal windows implementation
static BOOL inject_dll_launch_suspended_impl(
    const std::wstring& binary_path, const std::wstring& dll_path, const std::vector<std::string>& args,
    const std::map<std::string, std::string>& env_vars, DWORD* out_pid, bool interactive_resume,
    bool wait_for_completion, bool disable_aslr, int* out_exit_code
) {
  if (disable_aslr) {
    log_msg("starting Windows launch injection with suspended process (ASLR disabled)");
  } else {
    log_msg("starting Windows launch injection with suspended process");
  }

  // validate library exists
  if (GetFileAttributesW(dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
    std::stringstream ss;
    ss << "Library not found at path: " << std::string(dll_path.begin(), dll_path.end());
    log_msg(ss.str());
    return FALSE;
  }

  // validate binary exists
  if (GetFileAttributesW(binary_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
    std::stringstream ss;
    ss << "Binary not found at path: " << std::string(binary_path.begin(), binary_path.end());
    log_msg(ss.str());
    return FALSE;
  }

  // build command line
  std::wstring command_line = build_command_line(binary_path, args);

  {
    std::stringstream ss;
    ss << "Target binary: " << std::string(binary_path.begin(), binary_path.end());
    log_msg(ss.str());
  }

  // build environment block
  LPVOID environment_block = nullptr;
  if (!env_vars.empty()) {
    log_msg("building environment block");

    // Get current environment
    LPWCH current_env = GetEnvironmentStringsW();
    if (!current_env) {
      log_msg("failed to get current environment");
      return FALSE;
    }

    // parse current environment into a map
    std::map<std::wstring, std::wstring> env_map;
    LPWCH env_ptr = current_env;
    while (*env_ptr) {
      std::wstring env_entry(env_ptr);
      size_t eq_pos = env_entry.find(L'=');
      if (eq_pos != std::wstring::npos) {
        std::wstring key = env_entry.substr(0, eq_pos);
        std::wstring value = env_entry.substr(eq_pos + 1);
        env_map[key] = value;
      }
      env_ptr += env_entry.length() + 1;
    }
    FreeEnvironmentStringsW(current_env);

    // add/override with custom environment variables
    for (const auto& [key, value] : env_vars) {
      std::wstring wkey = string_to_wstring(key);
      std::wstring wvalue = string_to_wstring(value);
      env_map[wkey] = wvalue;

      std::stringstream ss;
      ss << "setting environment variable: " << key << "=" << value;
      log_msg(ss.str());
    }

    // build environment block
    std::wstring env_block;
    for (const auto& [key, value] : env_map) {
      env_block += key + L"=" + value + L'\0';
    }
    env_block += L'\0'; // Double null terminator

    // Allocate memory for environment block
    size_t env_size = env_block.size() * sizeof(wchar_t);
    environment_block = malloc(env_size);
    if (!environment_block) {
      log_msg("failed to allocate memory for environment block");
      return FALSE;
    }
    memcpy(environment_block, env_block.c_str(), env_size);

    std::stringstream ss;
    ss << "environment block created with " << env_map.size() << " variables";
    log_msg(ss.str());
  }

  {
    std::stringstream ss;
    ss << "command line: " << std::string(command_line.begin(), command_line.end());
    log_msg(ss.str());
  }

  {
    std::stringstream ss;
    ss << "library to inject: " << std::string(dll_path.begin(), dll_path.end());
    log_msg(ss.str());
  }

  // create process in suspended state
  PROCESS_INFORMATION pi = {0};

  // createProcessW modifies the command line, so we need a mutable copy
  std::vector<wchar_t> cmd_line_buffer(command_line.begin(), command_line.end());
  cmd_line_buffer.push_back(L'\0');

  DWORD creation_flags = CREATE_SUSPENDED;
  if (environment_block) {
    creation_flags |= CREATE_UNICODE_ENVIRONMENT;
  }

  BOOL create_result = FALSE;

  if (disable_aslr) {
    log_msg("creating suspended process with ASLR disabled");

    // Use extended startup info for process mitigation policy
    STARTUPINFOEXW siex = {0};
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    // Initialize attribute list
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);

    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = (LPPROC_THREAD_ATTRIBUTE_LIST) malloc(attr_size);
    if (!attr_list) {
      log_msg("failed to allocate memory for attribute list");
      if (environment_block) {
        free(environment_block);
      }
      return FALSE;
    }

    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
      DWORD error = GetLastError();
      std::stringstream ss;
      ss << "Failed to initialize attribute list. Error code: " << error;
      log_msg(ss.str());
      free(attr_list);
      if (environment_block) {
        free(environment_block);
      }
      return FALSE;
    }

    // Set mitigation policy to disable ASLR
    DWORD64 mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF;

    if (!UpdateProcThreadAttribute(
            attr_list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation_policy, sizeof(mitigation_policy), NULL,
            NULL
        )) {
      DWORD error = GetLastError();
      std::stringstream ss;
      ss << "Failed to update mitigation policy attribute. Error code: " << error;
      log_msg(ss.str());
      DeleteProcThreadAttributeList(attr_list);
      free(attr_list);
      if (environment_block) {
        free(environment_block);
      }
      return FALSE;
    }

    siex.lpAttributeList = attr_list;
    creation_flags |= EXTENDED_STARTUPINFO_PRESENT;

    create_result = CreateProcessW(
        binary_path.c_str(),    // lpApplicationName
        cmd_line_buffer.data(), // lpCommandLine (must be mutable)
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        TRUE,                   // bInheritHandles
        creation_flags,         // dwCreationFlags
        environment_block,      // lpEnvironment
        NULL,                   // lpCurrentDirectory
        (LPSTARTUPINFOW) &siex, // lpStartupInfo
        &pi                     // lpProcessInformation
    );

    // Clean up attribute list
    DeleteProcThreadAttributeList(attr_list);
    free(attr_list);

  } else {
    log_msg("creating suspended process");

    STARTUPINFOW si = {0};
    si.cb = sizeof(si);

    create_result = CreateProcessW(
        binary_path.c_str(),    // lpApplicationName
        cmd_line_buffer.data(), // lpCommandLine (must be mutable)
        NULL,                   // lpProcessAttributes
        NULL,                   // lpThreadAttributes
        TRUE,                   // bInheritHandles
        creation_flags,         // dwCreationFlags
        environment_block,      // lpEnvironment
        NULL,                   // lpCurrentDirectory
        &si,                    // lpStartupInfo
        &pi                     // lpProcessInformation
    );
  }

  if (!create_result) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to create suspended process. Error code: " << error;
    log_msg(ss.str());
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  {
    std::stringstream ss;
    ss << "process created successfully with PID: " << pi.dwProcessId;
    log_msg(ss.str());
  }

  // get address of LoadLibraryW function
  log_msg("getting address of LoadLibraryW");
  LPTHREAD_START_ROUTINE load_library_addr =
      (LPTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

  if (!load_library_addr) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to get address of LoadLibraryW. Error code: " << error;
    log_msg(ss.str());
    TerminateProcess(pi.hProcess, -1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  {
    std::stringstream ss;
    ss << "loadLibraryW address obtained: " << std::hex << load_library_addr;
    log_msg(ss.str());
  }

  // allocate memory in the target process for the DLL path
  log_msg("allocating memory in suspended process");
  SIZE_T dll_path_size = (dll_path.length() + 1) * sizeof(wchar_t);
  LPVOID remote_memory = VirtualAllocEx(pi.hProcess, NULL, dll_path_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  if (!remote_memory) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to allocate memory in suspended process. Error code: " << error;
    log_msg(ss.str());
    TerminateProcess(pi.hProcess, -1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  log_msg("memory allocated successfully");

  // write the DLL path to the allocated memory
  log_msg("writing DLL path to process memory");
  SIZE_T bytes_written;
  if (!WriteProcessMemory(pi.hProcess, remote_memory, dll_path.c_str(), dll_path_size, &bytes_written)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to write DLL path to process memory. Error code: " << error;
    log_msg(ss.str());
    VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, -1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  if (bytes_written != dll_path_size) {
    log_msg("incomplete write to process memory");
    VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, -1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  log_msg("DLL path written successfully");

  // create remote thread to load the library
  log_msg("creating remote thread to load library");
  HANDLE remote_thread = CreateRemoteThread(pi.hProcess, NULL, 0, load_library_addr, remote_memory, 0, NULL);

  if (!remote_thread) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to create remote thread. Error code: " << error;
    log_msg(ss.str());
    VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, -1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  log_msg("remote thread created successfully");

  // wait for the remote thread to complete (library loading)
  log_msg("waiting for library loading to complete");
  DWORD wait_result = WaitForSingleObject(remote_thread, INFINITE);
  if (wait_result != WAIT_OBJECT_0) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Wait for remote thread failed. Error code: " << error;
    log_msg(ss.str());
    CloseHandle(remote_thread);
    VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, -1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (environment_block) {
      free(environment_block);
    }
    return FALSE;
  }

  // check if library loading was successful
  DWORD exit_code;
  if (GetExitCodeThread(remote_thread, &exit_code)) {
    std::stringstream ss;
    ss << "library loading thread exit code: " << exit_code;
    log_msg(ss.str());
    if (exit_code == 0) {
      log_msg("warning: library loading may have failed (exit code is 0)");
    }
  }

  CloseHandle(remote_thread);
  VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);

  log_msg("library loading completed");

  if (interactive_resume) {
    std::stringstream ss;
    ss << "process created and suspended (PID: " << pi.dwProcessId << ")";
    log_msg(ss.str());

    // output to console for user interaction
    std::cout << "process created and suspended (PID: " << pi.dwProcessId << ")" << std::endl;
    std::cout << "binary: " << std::string(binary_path.begin(), binary_path.end()) << std::endl;
    std::cout << "DLL injected successfully. Press Enter to resume process..." << std::endl;

    // wait for user input
    std::cin.get();

    log_msg("user resumed process, continuing execution");
  }

  // resume the main thread
  ResumeThread(pi.hThread);

  log_msg("process resumed successfully");

  // set output PID if requested
  if (out_pid) {
    *out_pid = pi.dwProcessId;
  }

  // conditionally wait for process completion based on configuration
  if (wait_for_completion) {
    log_msg("waiting for target process to complete");
    DWORD wait_result = WaitForSingleObject(pi.hProcess, INFINITE);

    if (wait_result != WAIT_OBJECT_0) {
      DWORD error = GetLastError();
      std::stringstream ss;
      ss << "Wait for process completion failed. Error code: " << error;
      log_msg(ss.str());
      // continue with cleanup, but note the error
    }

    // get process exit code
    DWORD process_exit_code = 0;
    if (GetExitCodeProcess(pi.hProcess, &process_exit_code)) {
      std::stringstream ss;
      ss << "target process completed with exit code: " << process_exit_code;
      log_msg(ss.str());
      if (out_exit_code) {
        *out_exit_code = static_cast<int>(process_exit_code);
      }
    } else {
      log_msg("failed to get process exit code");
    }
  } else {
    log_msg("process launched successfully - not waiting for completion");
  }

  // clean up handles
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  // clean up environment block
  if (environment_block) {
    free(environment_block);
  }

  {
    std::stringstream ss;
    ss << "launch injection completed successfully for PID: " << pi.dwProcessId;
    log_msg(ss.str());
  }

  return TRUE;
}

// clean wrapper for the public api
bool w1::inject::windows::inject_dll_launch_suspended(
    const std::wstring& binary_path, const std::wstring& dll_path, const std::vector<std::string>& args,
    const std::map<std::string, std::string>& env_vars, process_id* out_pid, bool interactive_resume,
    bool wait_for_completion, bool disable_aslr, int* out_exit_code
) {
  DWORD win_pid;
  BOOL result = inject_dll_launch_suspended_impl(
      binary_path, dll_path, args, env_vars, &win_pid, interactive_resume, wait_for_completion, disable_aslr,
      out_exit_code
  );
  if (out_pid) {
    *out_pid = static_cast<process_id>(win_pid);
  }
  return result != FALSE;
}