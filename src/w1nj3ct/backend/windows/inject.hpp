#pragma once

#include <map>
#include <string>
#include <vector>

// completely clean interface, no windows dependencies
namespace w1::inject::windows {

// opaque types for clean interface
using process_handle = void*;
using process_id = unsigned long;

// injection methods
bool inject_dll_create_remote_thread(process_handle h_process, const std::wstring& dll_path);
bool inject_dll_set_windows_hook_ex(process_handle h_process, process_id pid, const std::wstring& dll_path);
bool inject_dll_rtl_create_user_thread(process_handle h_process, const std::wstring& dll_path);
bool inject_dll_reflective_loader(process_handle h_process, const std::wstring& dll_path);
bool inject_dll_launch_suspended(
    const std::wstring& binary_path, 
    const std::wstring& dll_path, 
    const std::vector<std::string>& args,
    const std::map<std::string, std::string>& env_vars, 
    process_id* out_pid, 
    bool interactive_resume,
    bool wait_for_completion
);

}
