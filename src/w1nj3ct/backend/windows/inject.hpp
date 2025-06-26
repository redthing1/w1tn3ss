#pragma once

#include <windows.h>

#include <psapi.h>
#include <tlhelp32.h>

#include "winapis.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

// define the type for the dll_main function
typedef BOOL(WINAPI* dll_main_t)(HINSTANCE, DWORD, LPVOID);

// - injection methods

BOOL inject_dll_create_remote_thread(HANDLE h_process, const std::wstring& dll_path);
BOOL inject_dll_set_windows_hook_ex(HANDLE h_process, DWORD process_id, const std::wstring& dll_path);
BOOL inject_dll_rtl_create_user_thread(HANDLE h_process, const std::wstring& dll_path);
BOOL inject_dll_reflective_loader(HANDLE h_process, const std::wstring& dll_path);
BOOL inject_dll_launch_suspended(
    const std::wstring& binary_path, const std::wstring& dll_path, const std::vector<std::string>& args,
    const std::map<std::string, std::string>& env_vars = {}, DWORD* out_pid = nullptr, bool interactive_resume = false,
    bool wait_for_completion = false
);
