#include "w1monitor/backend/windows/windows_module_monitor.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::windows {
namespace {

struct ldr_dll_notification_data {
  ULONG Flags;
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

std::string utf16_to_utf8(const UNICODE_STRING* value) {
  if (!value || !value->Buffer || value->Length == 0) {
    return {};
  }
  const int wchar_len = static_cast<int>(value->Length / sizeof(WCHAR));
  if (wchar_len <= 0) {
    return {};
  }
  const int required = WideCharToMultiByte(CP_UTF8, 0, value->Buffer, wchar_len, nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return {};
  }
  std::string out(static_cast<size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value->Buffer, wchar_len, out.data(), required, nullptr, nullptr);
  return out;
}

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
    std::lock_guard<std::mutex> lock(modules_mutex_);
    modules_.clear();
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
      handle = monitor->original_loadlibrarya_(name);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
      }
    }
    return handle;
  }

  static HMODULE WINAPI replacement_loadlibraryw(LPCWSTR name) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibraryw_) {
      handle = monitor->original_loadlibraryw_(name);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
      }
    }
    return handle;
  }

  static HMODULE WINAPI replacement_loadlibraryexa(LPCSTR name, HANDLE file, DWORD flags) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibraryexa_) {
      handle = monitor->original_loadlibraryexa_(name, file, flags);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
      }
    }
    return handle;
  }

  static HMODULE WINAPI replacement_loadlibraryexw(LPCWSTR name, HANDLE file, DWORD flags) {
    auto* monitor = active_monitor;
    HMODULE handle = nullptr;
    if (monitor && monitor->original_loadlibraryexw_) {
      handle = monitor->original_loadlibraryexw_(name, file, flags);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
      }
    }
    return handle;
  }

  static BOOL WINAPI replacement_freelibrary(HMODULE module) {
    auto* monitor = active_monitor;
    BOOL result = FALSE;
    if (monitor && monitor->original_freelibrary_) {
      result = monitor->original_freelibrary_(module);
      if (monitor->active_) {
        monitor->refresh_snapshot(true);
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
    if (loadlibrarya_handle_.id != 0 || loadlibraryw_handle_.id != 0) {
      return;
    }

    auto attach_symbol = [&](const char* symbol, void* replacement, w1::h00k::hook_handle& handle_out,
                             void*& original_out) {
      w1::h00k::hook_request request{};
      request.target.kind = w1::h00k::hook_target_kind::symbol;
      request.target.symbol = symbol;
      request.replacement = replacement;
      request.preferred = w1::h00k::hook_technique::interpose;
      request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
      request.selection = w1::h00k::hook_selection::strict;

      void* original = nullptr;
      auto result = w1::h00k::attach(request, &original);
      if (result.error.ok()) {
        handle_out = result.handle;
        original_out = original;
      }
    };

    void* original = nullptr;
    attach_symbol("LoadLibraryA", reinterpret_cast<void*>(&windows_module_monitor::replacement_loadlibrarya),
                  loadlibrarya_handle_, original);
    original_loadlibrarya_ = reinterpret_cast<loadlibrarya_fn>(original);

    original = nullptr;
    attach_symbol("LoadLibraryW", reinterpret_cast<void*>(&windows_module_monitor::replacement_loadlibraryw),
                  loadlibraryw_handle_, original);
    original_loadlibraryw_ = reinterpret_cast<loadlibraryw_fn>(original);

    original = nullptr;
    attach_symbol("LoadLibraryExA", reinterpret_cast<void*>(&windows_module_monitor::replacement_loadlibraryexa),
                  loadlibraryexa_handle_, original);
    original_loadlibraryexa_ = reinterpret_cast<loadlibraryexa_fn>(original);

    original = nullptr;
    attach_symbol("LoadLibraryExW", reinterpret_cast<void*>(&windows_module_monitor::replacement_loadlibraryexw),
                  loadlibraryexw_handle_, original);
    original_loadlibraryexw_ = reinterpret_cast<loadlibraryexw_fn>(original);

    original = nullptr;
    attach_symbol("FreeLibrary", reinterpret_cast<void*>(&windows_module_monitor::replacement_freelibrary),
                  freelibrary_handle_, original);
    original_freelibrary_ = reinterpret_cast<freelibrary_fn>(original);
  }

  void detach_hooks() {
    if (loadlibrarya_handle_.id != 0) {
      (void)w1::h00k::detach(loadlibrarya_handle_);
      loadlibrarya_handle_ = {};
      original_loadlibrarya_ = nullptr;
    }
    if (loadlibraryw_handle_.id != 0) {
      (void)w1::h00k::detach(loadlibraryw_handle_);
      loadlibraryw_handle_ = {};
      original_loadlibraryw_ = nullptr;
    }
    if (loadlibraryexa_handle_.id != 0) {
      (void)w1::h00k::detach(loadlibraryexa_handle_);
      loadlibraryexa_handle_ = {};
      original_loadlibraryexa_ = nullptr;
    }
    if (loadlibraryexw_handle_.id != 0) {
      (void)w1::h00k::detach(loadlibraryexw_handle_);
      loadlibraryexw_handle_ = {};
      original_loadlibraryexw_ = nullptr;
    }
    if (freelibrary_handle_.id != 0) {
      (void)w1::h00k::detach(freelibrary_handle_);
      freelibrary_handle_ = {};
      original_freelibrary_ = nullptr;
    }
  }

  void refresh_snapshot(bool emit_events) {
    std::unordered_map<void*, module_event> next;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
      return;
    }

    MODULEENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
      do {
        module_event event{};
        event.type = module_event::kind::loaded;
        event.path = entry.szExePath;
        event.base = entry.modBaseAddr;
        event.size = entry.modBaseSize;
        if (event.base) {
          next[event.base] = event;
        }
        entry.dwSize = sizeof(entry);
      } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    std::lock_guard<std::mutex> lock(modules_mutex_);
    if (emit_events) {
      for (const auto& [base, event] : next) {
        if (modules_.find(base) == modules_.end()) {
          queue_.push(event);
        }
      }
      for (const auto& [base, event] : modules_) {
        if (next.find(base) == next.end()) {
          module_event out = event;
          out.type = module_event::kind::unloaded;
          queue_.push(out);
        }
      }
    }
    modules_ = std::move(next);
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
    queue_.push(event);
  }

  void track_module(void* base, const UNICODE_STRING* full_name, size_t size) {
    if (!base) {
      return;
    }
    module_event event{};
    event.type = module_event::kind::loaded;
    event.path = utf16_to_utf8(full_name);
    event.base = base;
    event.size = size;
    std::lock_guard<std::mutex> lock(modules_mutex_);
    modules_[base] = event;
  }

  void untrack_module(void* base) {
    if (!base) {
      return;
    }
    std::lock_guard<std::mutex> lock(modules_mutex_);
    modules_.erase(base);
  }

  static inline windows_module_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};
  std::mutex modules_mutex_{};
  std::unordered_map<void*, module_event> modules_{};

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
