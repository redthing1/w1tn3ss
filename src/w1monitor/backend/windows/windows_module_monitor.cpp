#include "w1monitor/backend/windows/windows_module_monitor.hpp"

#include <memory>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/backend/module_snapshot.hpp"
#include "w1monitor/backend/hook_helpers.hpp"
#include "w1monitor/backend/windows/windows_string_utils.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::windows {
namespace {

struct ldr_dll_notification_data {
  ULONG Flags;
  union {
    struct {
      const UNICODE_STRING* FullDllName;
      const UNICODE_STRING* BaseDllName;
      PVOID DllBase;
      ULONG SizeOfImage;
    } Loaded;
    struct {
      const UNICODE_STRING* FullDllName;
      const UNICODE_STRING* BaseDllName;
      PVOID DllBase;
      ULONG SizeOfImage;
    } Unloaded;
  };
};

using ldr_dll_notify_fn = VOID (CALLBACK*)(ULONG reason, const ldr_dll_notification_data* data, void* context);
using ldr_register_fn = NTSTATUS (NTAPI*)(ULONG, ldr_dll_notify_fn, void*, void**);
using ldr_unregister_fn = NTSTATUS (NTAPI*)(void*);

static constexpr ULONG kLdrLoaded = 1;
static constexpr ULONG kLdrUnloaded = 2;

using loadlibrarya_fn = HMODULE(WINAPI*)(LPCSTR);
using loadlibraryw_fn = HMODULE(WINAPI*)(LPCWSTR);
using loadlibraryexa_fn = HMODULE(WINAPI*)(LPCSTR, HANDLE, DWORD);
using loadlibraryexw_fn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using freelibrary_fn = BOOL(WINAPI*)(HMODULE);

static thread_local bool g_snapshot_active = false;
static thread_local bool g_loader_hook_active = false;

struct loader_hook_guard {
  bool& flag;
  bool active = false;

  explicit loader_hook_guard(bool& flag_ref) : flag(flag_ref), active(!flag_ref) {
    if (active) {
      flag = true;
    }
  }

  ~loader_hook_guard() {
    if (active) {
      flag = false;
    }
  }
};

class windows_module_monitor final : public module_monitor {
public:
  void start() override {
    if (active_) {
      return;
    }
    active_ = true;
    active_monitor = this;

    refresh_snapshot(false);
    if (!register_notifications()) {
      install_hooks();
    }
  }

  void stop() override {
    active_ = false;
    if (active_monitor == this) {
      active_monitor = nullptr;
    }

    if (cookie_ && unregister_fn_) {
      unregister_fn_(cookie_);
      cookie_ = nullptr;
    }

    detach_hooks();

    queue_.clear();
    snapshot_.clear();
  }

  bool poll(module_event& out) override { return queue_.poll(out); }

private:
  static void CALLBACK on_dll_notification(ULONG reason, const ldr_dll_notification_data* data, void* context) {
    auto* monitor = static_cast<windows_module_monitor*>(context);
    if (!monitor || !monitor->active_ || !data) {
      return;
    }
    if (reason == kLdrLoaded) {
      monitor->emit_module(data->Loaded.FullDllName, data->Loaded.DllBase, data->Loaded.SizeOfImage,
                           module_event::kind::loaded);
      monitor->track_module(data->Loaded.DllBase, data->Loaded.FullDllName, data->Loaded.SizeOfImage);
    } else if (reason == kLdrUnloaded) {
      monitor->emit_module(data->Unloaded.FullDllName, data->Unloaded.DllBase, data->Unloaded.SizeOfImage,
                           module_event::kind::unloaded);
      monitor->untrack_module(data->Unloaded.DllBase);
    }
  }

  static HMODULE WINAPI replacement_loadlibrarya(LPCSTR name) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibrarya_) {
      loader_hook_guard guard(g_loader_hook_active);
      if (!guard.active) {
        return monitor->original_loadlibrarya_(name);
      }
      handle = monitor->original_loadlibrarya_(name);
      if (monitor->active_ && !g_snapshot_active) {
        g_snapshot_active = true;
        monitor->refresh_snapshot(true);
        g_snapshot_active = false;
      }
    }
    return handle;
  }

  static HMODULE WINAPI replacement_loadlibraryw(LPCWSTR name) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibraryw_) {
      loader_hook_guard guard(g_loader_hook_active);
      if (!guard.active) {
        return monitor->original_loadlibraryw_(name);
      }
      handle = monitor->original_loadlibraryw_(name);
      if (monitor->active_ && !g_snapshot_active) {
        g_snapshot_active = true;
        monitor->refresh_snapshot(true);
        g_snapshot_active = false;
      }
    }
    return handle;
  }

  static HMODULE WINAPI replacement_loadlibraryexa(LPCSTR name, HANDLE file, DWORD flags) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibraryexa_) {
      loader_hook_guard guard(g_loader_hook_active);
      if (!guard.active) {
        return monitor->original_loadlibraryexa_(name, file, flags);
      }
      handle = monitor->original_loadlibraryexa_(name, file, flags);
      if (monitor->active_ && !g_snapshot_active) {
        g_snapshot_active = true;
        monitor->refresh_snapshot(true);
        g_snapshot_active = false;
      }
    }
    return handle;
  }

  static HMODULE WINAPI replacement_loadlibraryexw(LPCWSTR name, HANDLE file, DWORD flags) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibraryexw_) {
      loader_hook_guard guard(g_loader_hook_active);
      if (!guard.active) {
        return monitor->original_loadlibraryexw_(name, file, flags);
      }
      handle = monitor->original_loadlibraryexw_(name, file, flags);
      if (monitor->active_ && !g_snapshot_active) {
        g_snapshot_active = true;
        monitor->refresh_snapshot(true);
        g_snapshot_active = false;
      }
    }
    return handle;
  }

  static BOOL WINAPI replacement_freelibrary(HMODULE module) {
    auto* monitor = active_monitor;
    BOOL result = FALSE;
    if (monitor && monitor->original_freelibrary_) {
      loader_hook_guard guard(g_loader_hook_active);
      if (!guard.active) {
        return monitor->original_freelibrary_(module);
      }
      result = monitor->original_freelibrary_(module);
      if (monitor->active_ && !g_snapshot_active) {
        g_snapshot_active = true;
        monitor->refresh_snapshot(true);
        g_snapshot_active = false;
      }
    }
    return result;
  }

  bool register_notifications() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
      return false;
    }

    auto register_fn = reinterpret_cast<ldr_register_fn>(GetProcAddress(ntdll, "LdrRegisterDllNotification"));
    unregister_fn_ = reinterpret_cast<ldr_unregister_fn>(GetProcAddress(ntdll, "LdrUnregisterDllNotification"));
    if (!register_fn || !unregister_fn_) {
      return false;
    }

    NTSTATUS status = register_fn(0, &windows_module_monitor::on_dll_notification, this, &cookie_);
    if (status != 0) {
      cookie_ = nullptr;
      return false;
    }

    return true;
  }

  void install_hooks() {
    if (loadlibrarya_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "LoadLibraryA", &windows_module_monitor::replacement_loadlibrarya,
          loadlibrarya_handle_, original_loadlibrarya_);
    }

    if (loadlibraryw_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "LoadLibraryW", &windows_module_monitor::replacement_loadlibraryw,
          loadlibraryw_handle_, original_loadlibraryw_);
    }

    if (loadlibraryexa_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "LoadLibraryExA", &windows_module_monitor::replacement_loadlibraryexa,
          loadlibraryexa_handle_, original_loadlibraryexa_);
    }

    if (loadlibraryexw_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "LoadLibraryExW", &windows_module_monitor::replacement_loadlibraryexw,
          loadlibraryexw_handle_, original_loadlibraryexw_);
    }

    if (freelibrary_handle_.id == 0) {
      (void)hook_helpers::attach_interpose_symbol(
          "FreeLibrary", &windows_module_monitor::replacement_freelibrary,
          freelibrary_handle_, original_freelibrary_);
    }
  }

  void detach_hooks() {
    hook_helpers::detach_if_attached(loadlibrarya_handle_);
    original_loadlibrarya_ = nullptr;
    hook_helpers::detach_if_attached(loadlibraryw_handle_);
    original_loadlibraryw_ = nullptr;
    hook_helpers::detach_if_attached(loadlibraryexa_handle_);
    original_loadlibraryexa_ = nullptr;
    hook_helpers::detach_if_attached(loadlibraryexw_handle_);
    original_loadlibraryexw_ = nullptr;
    hook_helpers::detach_if_attached(freelibrary_handle_);
    original_freelibrary_ = nullptr;
  }

  void refresh_snapshot(bool emit_events) {
    std::vector<module_snapshot_entry> next;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
      return;
    }

    MODULEENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
      do {
        module_snapshot_entry event{};
        event.path = entry.szExePath;
        event.base = entry.modBaseAddr;
        event.size = entry.modBaseSize;
        if (event.base) {
          next.push_back(std::move(event));
        }
        entry.dwSize = sizeof(entry);
      } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    snapshot_.refresh(next, emit_events, [&](const module_event& event) {
      queue_.push(event);
    });
  }

  void emit_module(const UNICODE_STRING* full_name, void* base, size_t size, module_event::kind kind) {
    if (!base) {
      return;
    }
    module_event event{};
    event.type = kind;
    event.path = utf16_to_utf8(full_name);
    event.base = base;
    event.size = size;
    snapshot_.fill_missing(event);
    queue_.push(event);
  }

  void track_module(void* base, const UNICODE_STRING* full_name, size_t size) {
    snapshot_.track(base, utf16_to_utf8(full_name), size);
  }

  void untrack_module(void* base) {
    snapshot_.untrack(base);
  }

  static inline windows_module_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};
  module_snapshot_tracker snapshot_{};

  void* cookie_ = nullptr;
  ldr_unregister_fn unregister_fn_ = nullptr;

  w1::h00k::hook_handle loadlibrarya_handle_{};
  w1::h00k::hook_handle loadlibraryw_handle_{};
  w1::h00k::hook_handle loadlibraryexa_handle_{};
  w1::h00k::hook_handle loadlibraryexw_handle_{};
  w1::h00k::hook_handle freelibrary_handle_{};

  loadlibrarya_fn original_loadlibrarya_ = nullptr;
  loadlibraryw_fn original_loadlibraryw_ = nullptr;
  loadlibraryexa_fn original_loadlibraryexa_ = nullptr;
  loadlibraryexw_fn original_loadlibraryexw_ = nullptr;
  freelibrary_fn original_freelibrary_ = nullptr;
};

} // namespace

std::unique_ptr<module_monitor> make_module_monitor() {
  return std::make_unique<windows_module_monitor>();
}

} // namespace w1::monitor::backend::windows
