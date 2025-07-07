#include <sstream>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include "winapis.h"
#include "inject.hpp"
#include "util.hpp"

// internal windows implementation
static BOOL inject_dll_rtl_create_user_thread_impl(HANDLE h_process, const std::wstring& dll_path) {
  log_msg("starting RtlCreateUserThread injection method");

  // allocate memory in the target process for the dll path
  log_msg("allocating memory in the target process");
  LPVOID remote_memory = VirtualAllocEx(h_process, NULL, dll_path.size() * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
  if (!remote_memory) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to allocate memory in the target process. Error code: " << error;
    log_msg(ss.str());
    return FALSE;
  }
  log_msg("memory allocated successfully");

  // write the dll path to the allocated memory in the target process
  log_msg("writing DLL path to the allocated memory");
  SIZE_T bytes_written;
  if (!WriteProcessMemory(
          h_process, remote_memory, dll_path.c_str(), dll_path.size() * sizeof(wchar_t), &bytes_written
      )) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to write to process memory. Error code: " << error;
    log_msg(ss.str());
    VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  if (bytes_written != dll_path.size() * sizeof(wchar_t)) {
    log_msg("incomplete write to process memory");
    VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  log_msg("DLL path written successfully");

  // get the address of LoadLibraryW function
  log_msg("getting address of LoadLibraryW");
  LPTHREAD_START_ROUTINE load_library_addr =
      (LPTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
  if (!load_library_addr) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to get address of LoadLibraryW. Error code: " << error;
    log_msg(ss.str());
    VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  {
    std::stringstream ss;
    ss << "loadLibraryW address obtained: " << std::hex << load_library_addr;
    log_msg(ss.str());
  }

  // get the address of RtlCreateUserThread function
  log_msg("getting address of RtlCreateUserThread");
  pRtlCreateUserThread RtlCreateUserThread =
      (pRtlCreateUserThread) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlCreateUserThread");
  if (!RtlCreateUserThread) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to get address of RtlCreateUserThread. Error code: " << error;
    log_msg(ss.str());
    VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  {
    std::stringstream ss;
    ss << "rtlCreateUserThread address obtained: " << std::hex << (void*) RtlCreateUserThread;
    log_msg(ss.str());
  }

  // create a remote thread using RtlCreateUserThread
  log_msg("creating remote thread using RtlCreateUserThread");
  HANDLE h_thread = NULL;
  DWORD status =
      RtlCreateUserThread(h_process, NULL, FALSE, 0, NULL, NULL, load_library_addr, remote_memory, &h_thread, NULL);

  if (status != 0) {
    std::stringstream ss;
    ss << "Failed to create remote thread. Status: " << std::hex << status;
    log_msg(ss.str());
    VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  log_msg("remote thread created successfully");

  // wait for the remote thread to finish executing
  log_msg("waiting for remote thread to finish");
  DWORD wait_result = WaitForSingleObject(h_thread, INFINITE);
  if (wait_result != WAIT_OBJECT_0) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "WaitForSingleObject failed. Error code: " << error;
    log_msg(ss.str());
    CloseHandle(h_thread);
    VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE);
    return FALSE;
  }
  log_msg("remote thread finished execution");

  // get the exit code of the remote thread to check if dll injection was successful
  DWORD exit_code;
  if (GetExitCodeThread(h_thread, &exit_code)) {
    std::stringstream ss;
    ss << "remote thread exit code: " << exit_code;
    log_msg(ss.str());
    if (exit_code == 0) {
      log_msg("DLL injection may have failed (exit code is 0)");
    }
  } else {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to get remote thread exit code. Error code: " << error;
    log_msg(ss.str());
  }

  // clean up resources
  log_msg("cleaning up");
  if (!VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)) {
    DWORD error = GetLastError();
    std::stringstream ss;
    ss << "Failed to free memory in target process. Error code: " << error;
    log_msg(ss.str());
  }
  CloseHandle(h_thread);

  log_msg("RtlCreateUserThread injection completed");
  return TRUE;
}

// clean wrapper for the public api
bool w1::inject::windows::inject_dll_rtl_create_user_thread(process_handle h_process, const std::wstring& dll_path) {
  HANDLE win_handle = static_cast<HANDLE>(h_process);
  BOOL result = inject_dll_rtl_create_user_thread_impl(win_handle, dll_path);
  return result != FALSE;
}
