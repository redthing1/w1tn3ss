#include "w1monitor/backend/windows/windows_thread_monitor.hpp"

#include <memory>
#include <windows.h>

#include "w1h00k/hook.hpp"
#include "w1monitor/backend/hook_helpers.hpp"
#include "w1monitor/backend/thread_entry.hpp"
#include "w1monitor/backend/thread_event_helpers.hpp"
#include "w1monitor/backend/windows/windows_string_utils.hpp"
#include "w1monitor/event_queue.hpp"

namespace w1::monitor::backend::windows {
namespace {

using create_thread_fn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using exit_thread_fn = VOID(WINAPI*)(DWORD);
using set_thread_description_fn = HRESULT(WINAPI*)(HANDLE, PCWSTR);

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

    hook_helpers::detach_if_attached(base_thread_init_handle_);
    hook_helpers::detach_if_attached(rtl_exit_user_handle_);
    hook_helpers::detach_if_attached(create_thread_handle_);
    original_create_thread_ = nullptr;
    hook_helpers::detach_if_attached(exit_thread_handle_);
    original_exit_thread_ = nullptr;
    hook_helpers::detach_if_attached(set_description_handle_);
    original_set_description_ = nullptr;

    use_native_start_ = false;
    use_native_stop_ = false;

    queue_.clear();
  }

  bool poll(thread_event& out) override { return queue_.poll(out); }
  void set_entry_callback(thread_entry_callback callback) override { entry_callback_ = std::move(callback); }

private:
  struct start_payload {
    LPTHREAD_START_ROUTINE start_routine = nullptr;
    void* arg = nullptr;
    class windows_thread_monitor* monitor = nullptr;
  };

  static void prehook_base_thread_init_thunk(w1::h00k::hook_info* info) {
    (void)info;
    auto* monitor = active_monitor;
    if (!monitor || !monitor->active_) {
      return;
    }
    monitor->emitter_.started(static_cast<uint64_t>(GetCurrentThreadId()));
  }

  static void prehook_rtl_exit_user_thread(w1::h00k::hook_info* info) {
    (void)info;
    auto* monitor = active_monitor;
    if (!monitor || !monitor->active_) {
      return;
    }
    monitor->emitter_.stopped(static_cast<uint64_t>(GetCurrentThreadId()));
  }

  static DWORD WINAPI start_trampoline(LPVOID param) {
    std::unique_ptr<start_payload> payload(static_cast<start_payload*>(param));
    windows_thread_monitor* monitor = payload->monitor;
    LPTHREAD_START_ROUTINE start_routine = payload->start_routine;
    void* start_arg = payload->arg;

    if (monitor) {
      monitor->stop_tracker_.reset();
    }
    if (monitor && monitor->active_ && !monitor->use_native_start_) {
      monitor->emitter_.started(static_cast<uint64_t>(GetCurrentThreadId()));
    }

    DWORD result = 0;
    if (monitor) {
      const uint64_t result_value = backend::dispatch_thread_entry(
          monitor->entry_callback_,
          thread_entry_kind::win32,
          static_cast<uint64_t>(GetCurrentThreadId()),
          reinterpret_cast<void*>(start_routine),
          start_arg,
          [&]() -> uint64_t {
            if (start_routine) {
              return static_cast<uint64_t>(start_routine(start_arg));
            }
            return 0;
          });
      result = static_cast<DWORD>(result_value);
    } else if (start_routine) {
      result = start_routine(start_arg);
    }

    if (monitor && monitor->active_ && !monitor->use_native_stop_ && monitor->stop_tracker_.should_emit()) {
      monitor->emitter_.stopped(static_cast<uint64_t>(GetCurrentThreadId()));
    }

    return result;
  }

  static HANDLE WINAPI replacement_create_thread(LPSECURITY_ATTRIBUTES attrs, SIZE_T stack,
                                                 LPTHREAD_START_ROUTINE start, LPVOID param,
                                                 DWORD flags, LPDWORD thread_id) {
    auto* monitor = active_monitor;
    HANDLE handle = nullptr;
    if (monitor && monitor->original_create_thread_) {
      auto* payload = new start_payload{};
      payload->start_routine = start;
      payload->arg = param;
      payload->monitor = monitor;
      handle = monitor->original_create_thread_(attrs, stack, &windows_thread_monitor::start_trampoline, payload,
                                                flags, thread_id);
      if (!handle) {
        delete payload;
      }
    }
    return handle;
  }

  static VOID WINAPI replacement_exit_thread(DWORD code) {
    auto* monitor = active_monitor;
    if (monitor && monitor->active_ && !monitor->use_native_stop_ && monitor->stop_tracker_.should_emit()) {
      monitor->emitter_.stopped(static_cast<uint64_t>(GetCurrentThreadId()));
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
        monitor->emitter_.renamed(static_cast<uint64_t>(tid), utf16_to_utf8(name));
      }
    }
    return hr;
  }

  void install_native_hooks() {
    if (base_thread_init_handle_.id == 0) {
      if (hook_helpers::attach_inline_instrument("BaseThreadInitThunk", "kernel32.dll",
                                                 &windows_thread_monitor::prehook_base_thread_init_thunk,
                                                 base_thread_init_handle_)) {
        use_native_start_ = true;
      }
    }

    if (rtl_exit_user_handle_.id == 0) {
      if (hook_helpers::attach_inline_instrument("RtlExitUserThread", "ntdll.dll",
                                                 &windows_thread_monitor::prehook_rtl_exit_user_thread,
                                                 rtl_exit_user_handle_)) {
        use_native_stop_ = true;
      }
    }
  }

  void install_create_hook() {
    if (create_thread_handle_.id != 0) {
      return;
    }

    (void)hook_helpers::attach_interpose_symbol(
        "CreateThread", &windows_thread_monitor::replacement_create_thread,
        create_thread_handle_, original_create_thread_);
  }

  void install_exit_hook() {
    if (exit_thread_handle_.id != 0) {
      return;
    }

    (void)hook_helpers::attach_interpose_symbol(
        "ExitThread", &windows_thread_monitor::replacement_exit_thread,
        exit_thread_handle_, original_exit_thread_);
  }

  void install_set_description_hook() {
    if (set_description_handle_.id != 0) {
      return;
    }

    if (hook_helpers::attach_inline_replace(
            "SetThreadDescription", "kernel32.dll",
            &windows_thread_monitor::replacement_set_thread_description,
            set_description_handle_, original_set_description_)) {
      return;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32 || !GetProcAddress(kernel32, "SetThreadDescription")) {
      return;
    }

    (void)hook_helpers::attach_interpose_symbol(
        "SetThreadDescription",
        &windows_thread_monitor::replacement_set_thread_description,
        set_description_handle_, original_set_description_);
  }

  void install_hooks() {
    install_native_hooks();
    install_create_hook();
    if (!use_native_stop_) {
      install_exit_hook();
    }
    install_set_description_hook();
  }

  static inline windows_thread_monitor* active_monitor = nullptr;
  bool active_ = false;
  bool use_native_start_ = false;
  bool use_native_stop_ = false;
  event_queue queue_{};
  thread_event_emitter emitter_{queue_};
  thread_stop_tracker stop_tracker_{};

  w1::h00k::hook_handle base_thread_init_handle_{};
  w1::h00k::hook_handle rtl_exit_user_handle_{};
  w1::h00k::hook_handle create_thread_handle_{};
  w1::h00k::hook_handle exit_thread_handle_{};
  w1::h00k::hook_handle set_description_handle_{};

  create_thread_fn original_create_thread_ = nullptr;
  exit_thread_fn original_exit_thread_ = nullptr;
  set_thread_description_fn original_set_description_ = nullptr;
  thread_entry_callback entry_callback_{};
};

} // namespace

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return std::make_unique<windows_thread_monitor>();
}

} // namespace w1::monitor::backend::windows
