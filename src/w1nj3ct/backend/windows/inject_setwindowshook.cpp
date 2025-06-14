#include "inject.hpp"
#include "util.hpp"

// hook procedure that will be called by the windows hook
LRESULT CALLBACK hook_proc(int n_code, WPARAM w_param, LPARAM l_param) {
  log_msg("hook_proc called");
  return CallNextHookEx(NULL, n_code, w_param, l_param);
}

BOOL inject_dll_set_windows_hook_ex(HANDLE h_process, DWORD process_id, const std::wstring& dll_path) {
  // this function injects a dll into a target process using the setwindowshookex method
  log_msg("starting setwindowshookex injection method");

  // load the dll into the current process
  log_msg("loading dll into current process");
  HMODULE h_module = LoadLibraryW(dll_path.c_str());
  if (!h_module) {
    log_msg("failed to load dll");
    return FALSE;
  }
  log_msg("dll loaded successfully");

  // get the address of the hook procedure from the loaded dll
  log_msg("getting address of hook_proc");
  HOOKPROC hook_proc = (HOOKPROC) GetProcAddress(h_module, "hook_proc");
  if (!hook_proc) {
    log_msg("failed to get address of hook_proc");
    FreeLibrary(h_module);
    return FALSE;
  }
  log_msg("hook_proc address obtained");

  // resume the main thread of the target process
  log_msg("resuming main thread of target process");
  if (ResumeThread(h_process) == -1) {
    log_msg("failed to resume thread");
    FreeLibrary(h_module);
    return FALSE;
  }

  // wait a bit to ensure the process has started
  Sleep(1000);

  // find a thread id for the target process
  log_msg("finding a thread id for the target process");
  DWORD thread_id = 0;
  HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (h_snapshot == INVALID_HANDLE_VALUE) {
    log_msg("failed to create thread snapshot");
    FreeLibrary(h_module);
    return FALSE;
  }

  THREADENTRY32 te;
  te.dwSize = sizeof(THREADENTRY32);
  if (Thread32First(h_snapshot, &te)) {
    do {
      if (te.th32OwnerProcessID == process_id) {
        thread_id = te.th32ThreadID;
        break;
      }
    } while (Thread32Next(h_snapshot, &te));
  }
  CloseHandle(h_snapshot);

  if (thread_id == 0) {
    log_msg("failed to find a thread for the target process");
    FreeLibrary(h_module);
    return FALSE;
  }
  log_msg("found thread id: " + std::to_string(thread_id));

  // set the windows hook
  log_msg("setting windows hook");
  HHOOK hook = SetWindowsHookEx(WH_GETMESSAGE, hook_proc, h_module, thread_id);
  if (!hook) {
    log_msg("failed to set windows hook");
    FreeLibrary(h_module);
    return FALSE;
  }
  log_msg("windows hook set successfully");

  // post a message to the thread to trigger the hook
  log_msg("posting message to trigger hook");
  if (!PostThreadMessage(thread_id, WM_NULL, 0, 0)) {
    log_msg("failed to post thread message");
    // continue anyway, as the hook might still work
  }

  // wait a bit to ensure the hook has been triggered
  Sleep(1000);

  // unhook and clean up
  log_msg("unhooking and cleaning up");
  UnhookWindowsHookEx(hook);
  FreeLibrary(h_module);

  log_msg("setwindowshookex injection completed successfully");
  return TRUE;
}
