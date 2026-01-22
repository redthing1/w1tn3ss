#include "w1monitor/backend/windows/windows_thread_monitor.hpp"

#include <memory>
#include <string>

#include <windows.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::windows {
namespace {

using create_thread_fn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using exit_thread_fn = VOID(WINAPI*)(DWORD);
using set_thread_description_fn = HRESULT(WINAPI*)(HANDLE, PCWSTR);

std::string utf16_to_utf8(PCWSTR value) {
  if (!value) {
    return {};
  }
  const int wchar_len = static_cast<int>(wcslen(value));
  if (wchar_len <= 0) {
    return {};
  }
  const int required = WideCharToMultiByte(CP_UTF8, 0, value, wchar_len, nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return {};
  }
  std::string out(static_cast<size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, wchar_len, out.data(), required, nullptr, nullptr);
  return out;
}

class windows_thread_monitor final : public thread_monitor {
public:
  void start() override {
    if (active_) {
      return;
    }
    active_ = true;
    active_monitor = this;
    install_hooks();
  }

  void stop() override {
    active_ = false;
    if (active_monitor == this) {
      active_monitor = nullptr;
    }

    if (create_thread_handle_.id != 0) {
      (void)w1::h00k::detach(create_thread_handle_);
      create_thread_handle_ = {};
      original_create_thread_ = nullptr;
    }
    if (exit_thread_handle_.id != 0) {
      (void)w1::h00k::detach(exit_thread_handle_);
      exit_thread_handle_ = {};
      original_exit_thread_ = nullptr;
    }
    if (set_description_handle_.id != 0) {
      (void)w1::h00k::detach(set_description_handle_);
      set_description_handle_ = {};
      original_set_description_ = nullptr;
    }

    queue_.clear();
  }

  bool poll(thread_event& out) override { return queue_.poll(out); }

private:
  static HANDLE WINAPI replacement_create_thread(LPSECURITY_ATTRIBUTES attrs, SIZE_T stack,
                                                 LPTHREAD_START_ROUTINE start, LPVOID param,
                                                 DWORD flags, LPDWORD thread_id) {
    auto* monitor = active_monitor;
    HANDLE handle = nullptr;
    if (monitor && monitor->original_create_thread_) {
      handle = monitor->original_create_thread_(attrs, stack, start, param, flags, thread_id);
      if (monitor->active_ && handle) {
        DWORD tid = thread_id ? *thread_id : GetThreadId(handle);
        if (tid != 0) {
          monitor->emit_started(static_cast<uint64_t>(tid));
        }
      }
    }
    return handle;
  }

  static VOID WINAPI replacement_exit_thread(DWORD code) {
    auto* monitor = active_monitor;
    if (monitor && monitor->active_) {
      monitor->emit_stopped(static_cast<uint64_t>(GetCurrentThreadId()));
    }
    if (monitor && monitor->original_exit_thread_) {
      monitor->original_exit_thread_(code);
    }
  }

  static HRESULT WINAPI replacement_set_thread_description(HANDLE thread, PCWSTR name) {
    auto* monitor = active_monitor;
    HRESULT hr = E_FAIL;
    if (monitor && monitor->original_set_description_) {
      hr = monitor->original_set_description_(thread, name);
    }
    if (monitor && monitor->active_ && SUCCEEDED(hr) && name) {
      DWORD tid = GetThreadId(thread);
      if (tid != 0) {
        monitor->emit_renamed(static_cast<uint64_t>(tid), name);
      }
    }
    return hr;
  }

  void install_hooks() {
    if (create_thread_handle_.id != 0) {
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
    attach_symbol("CreateThread", reinterpret_cast<void*>(&windows_thread_monitor::replacement_create_thread),
                  create_thread_handle_, original);
    original_create_thread_ = reinterpret_cast<create_thread_fn>(original);

    original = nullptr;
    attach_symbol("ExitThread", reinterpret_cast<void*>(&windows_thread_monitor::replacement_exit_thread),
                  exit_thread_handle_, original);
    original_exit_thread_ = reinterpret_cast<exit_thread_fn>(original);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 && GetProcAddress(kernel32, "SetThreadDescription")) {
      original = nullptr;
      attach_symbol("SetThreadDescription",
                    reinterpret_cast<void*>(&windows_thread_monitor::replacement_set_thread_description),
                    set_description_handle_, original);
      original_set_description_ = reinterpret_cast<set_thread_description_fn>(original);
    }
  }

  void emit_started(uint64_t tid) {
    thread_event event{};
    event.type = thread_event::kind::started;
    event.tid = tid;
    queue_.push(event);
  }

  void emit_stopped(uint64_t tid) {
    thread_event event{};
    event.type = thread_event::kind::stopped;
    event.tid = tid;
    queue_.push(event);
  }

  void emit_renamed(uint64_t tid, PCWSTR name) {
    thread_event event{};
    event.type = thread_event::kind::renamed;
    event.tid = tid;
    event.name = utf16_to_utf8(name);
    queue_.push(event);
  }

  static inline windows_thread_monitor* active_monitor = nullptr;
  bool active_ = false;
  event_queue queue_{};

  w1::h00k::hook_handle create_thread_handle_{};
  w1::h00k::hook_handle exit_thread_handle_{};
  w1::h00k::hook_handle set_description_handle_{};

  create_thread_fn original_create_thread_ = nullptr;
  exit_thread_fn original_exit_thread_ = nullptr;
  set_thread_description_fn original_set_description_ = nullptr;
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<windows_thread_monitor>();
}

} // namespace w1::monitor::backend::windows
