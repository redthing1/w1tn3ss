#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include "inject.hpp"
#include "util.hpp"

// Convert std::string to std::wstring
std::wstring string_to_wstring(const std::string& str) {
  if (str.empty()) {
    return std::wstring();
  }
  int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
  std::wstring result(size - 1, 0);
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
  return result;
}

// Build command line string from binary path and arguments
std::wstring build_command_line(const std::wstring& binary_path, const std::vector<std::string>& args) {
  std::wstring cmd_line = L"\"" + binary_path + L"\"";

  for (const auto& arg : args) {
    cmd_line += L" \"" + string_to_wstring(arg) + L"\"";
  }

  return cmd_line;
}

BOOL inject_dll_launch_suspended(
    const std::wstring& binary_path, const std::wstring& dll_path, const std::vector<std::string>& args,
    const std::map<std::string, std::string>& env_vars, DWORD* out_pid, bool interactive_resume,
    bool wait_for_completion
) {
  log_msg("Starting Windows launch injection with suspended process");

  // Validate library exists
  if (GetFileAttributesW(dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
    std::stringstream ss;
    ss << "Library not found at path: " << std::string(dll_path.begin(), dll_path.end());
    log_msg(ss.str());
    return FALSE;
  }

  // Validate binary exists
  if (GetFileAttributesW(binary_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
    std::stringstream ss;
    ss << "Binary not found at path: " << std::string(binary_path.begin(), binary_path.end());
    log_msg(ss.str());
    return FALSE;
  }

  // Build command line
  std::wstring command_line = build_command_line(binary_path, args);

  {
    std::stringstream ss;
    ss << "Target binary: " << std::string(binary_path.begin(), binary_path.end());
    log_msg(ss.str());
  }

  // Build environment block
  LPVOID environment_block = nullptr;
  if (!env_vars.empty()) {
    log_msg("Building environment block");

    // Get current environment
    LPWCH current_env = GetEnvironmentStringsW();
    if (!current_env) {
      log_msg("Failed to get current environment");
      return FALSE;
    }

    // Parse current environment into a map
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

    // Add/override with custom environment variables
    for (const auto& [key, value] : env_vars) {
      std::wstring wkey = string_to_wstring(key);
      std::wstring wvalue = string_to_wstring(value);
      env_map[wkey] = wvalue;

      std::stringstream ss;
      ss << "Setting environment variable: " << key << "=" << value;
      log_msg(ss.str());
    }

    // Build environment block
    std::wstring env_block;
    for (const auto& [key, value] : env_map) {
      env_block += key + L"=" + value + L'\0';
    }
    env_block += L'\0'; // Double null terminator

    // Allocate memory for environment block
    size_t env_size = env_block.size() * sizeof(wchar_t);
    environment_block = malloc(env_size);
    if (!environment_block) {
      log_msg("Failed to allocate memory for environment block");
      return FALSE;
    }
    memcpy(environment_block, env_block.c_str(), env_size);

    std::stringstream ss;
    ss << "Environment block created with " << env_map.size() << " variables";
    log_msg(ss.str());
  }

  {
    std::stringstream ss;
    ss << "Command line: " << std::string(command_line.begin(), command_line.end());
    log_msg(ss.str());
  }

  {
    std::stringstream ss;
    ss << "Library to inject: " << std::string(dll_path.begin(), dll_path.end());
    log_msg(ss.str());
  }

  // Create process in suspended state
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof(si);

  log_msg("Creating suspended process");

  // CreateProcessW modifies the command line, so we need a mutable copy
  std::vector<wchar_t> cmd_line_buffer(command_line.begin(), command_line.end());
  cmd_line_buffer.push_back(L'\0');

  DWORD creation_flags = CREATE_SUSPENDED;
  if (environment_block) {
    creation_flags |= CREATE_UNICODE_ENVIRONMENT;
  }

  BOOL create_result = CreateProcessW(
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
    ss << "Process created successfully with PID: " << pi.dwProcessId;
    log_msg(ss.str());
  }

  // Get address of LoadLibraryW function
  log_msg("Getting address of LoadLibraryW");
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
    ss << "LoadLibraryW address obtained: " << std::hex << load_library_addr;
    log_msg(ss.str());
  }

  // Allocate memory in the target process for the DLL path
  log_msg("Allocating memory in suspended process");
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

  log_msg("Memory allocated successfully");

  // Write the DLL path to the allocated memory
  log_msg("Writing DLL path to process memory");
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
    log_msg("Incomplete write to process memory");
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

  // Create remote thread to load the library
  log_msg("Creating remote thread to load library");
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

  log_msg("Remote thread created successfully");

  // Wait for the remote thread to complete (library loading)
  log_msg("Waiting for library loading to complete");
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

  // Check if library loading was successful
  DWORD exit_code;
  if (GetExitCodeThread(remote_thread, &exit_code)) {
    std::stringstream ss;
    ss << "Library loading thread exit code: " << exit_code;
    log_msg(ss.str());
    if (exit_code == 0) {
      log_msg("Warning: Library loading may have failed (exit code is 0)");
    }
  }

  CloseHandle(remote_thread);
  VirtualFreeEx(pi.hProcess, remote_memory, 0, MEM_RELEASE);

  log_msg("Library loading completed");

  if (interactive_resume) {
    std::stringstream ss;
    ss << "Process created and suspended (PID: " << pi.dwProcessId << ")";
    log_msg(ss.str());
    
    // Output to console for user interaction
    std::cout << "Process created and suspended (PID: " << pi.dwProcessId << ")" << std::endl;
    std::cout << "Binary: " << std::string(binary_path.begin(), binary_path.end()) << std::endl;
    std::cout << "DLL injected successfully. Press Enter to resume process..." << std::endl;
    
    // Wait for user input
    std::cin.get();
    
    log_msg("User resumed process, continuing execution");
  }

  // Resume the main thread
  ResumeThread(pi.hThread);

  log_msg("Process resumed successfully");

  // Set output PID if requested
  if (out_pid) {
    *out_pid = pi.dwProcessId;
  }

  // Conditionally wait for process completion based on configuration
  if (wait_for_completion) {
    log_msg("Waiting for target process to complete");
    DWORD wait_result = WaitForSingleObject(pi.hProcess, INFINITE);
    
    if (wait_result != WAIT_OBJECT_0) {
      DWORD error = GetLastError();
      std::stringstream ss;
      ss << "Wait for process completion failed. Error code: " << error;
      log_msg(ss.str());
      // Continue with cleanup, but note the error
    }

    // Get process exit code
    DWORD process_exit_code = 0;
    if (GetExitCodeProcess(pi.hProcess, &process_exit_code)) {
      std::stringstream ss;
      ss << "Target process completed with exit code: " << process_exit_code;
      log_msg(ss.str());
    } else {
      log_msg("Failed to get process exit code");
    }
  } else {
    log_msg("Process launched successfully - not waiting for completion");
  }

  // Clean up handles
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  // Clean up environment block
  if (environment_block) {
    free(environment_block);
  }

  {
    std::stringstream ss;
    ss << "Launch injection completed successfully for PID: " << pi.dwProcessId;
    log_msg(ss.str());
  }

  return TRUE;
}