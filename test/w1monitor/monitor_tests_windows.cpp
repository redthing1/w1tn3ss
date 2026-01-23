#if defined(_WIN32)

#include "doctest/doctest.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

#include <windows.h>

#include "w1monitor/monitor_factory.hpp"
#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"
#include "monitor_test_helpers.hpp"
#include "test_paths.hpp"

namespace {

using w1::monitor::test::wait_for_event;

struct thread_name_params {
  std::atomic<uint64_t>* tid_out = nullptr;
  const wchar_t* name = nullptr;
  DWORD sleep_ms = 0;
};

DWORD WINAPI thread_start_with_name(LPVOID param) {
  auto* params = static_cast<thread_name_params*>(param);
  if (params && params->tid_out) {
    params->tid_out->store(static_cast<uint64_t>(GetCurrentThreadId()), std::memory_order_release);
  }
  if (params && params->name) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
      auto set_desc = reinterpret_cast<HRESULT(WINAPI*)(HANDLE, PCWSTR)>(
          GetProcAddress(kernel32, "SetThreadDescription"));
      if (set_desc) {
        set_desc(GetCurrentThread(), params->name);
      }
    }
  }
  if (params && params->sleep_ms > 0) {
    Sleep(params->sleep_ms);
  }
  return 0;
}

DWORD WINAPI thread_start_record_tid(LPVOID param) {
  auto* tid_ptr = static_cast<std::atomic<uint64_t>*>(param);
  if (tid_ptr) {
    tid_ptr->store(static_cast<uint64_t>(GetCurrentThreadId()), std::memory_order_release);
  }
  Sleep(25);
  return 0;
}

DWORD WINAPI thread_start_set_flag(LPVOID param) {
  auto* flag = static_cast<std::atomic<bool>*>(param);
  if (flag) {
    flag->store(true, std::memory_order_release);
  }
  return 7;
}

} // namespace

TEST_CASE("w1monitor windows module monitor reports load/unload") {
  auto monitor = w1::monitor::make_module_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  const char* lib_name = w1::test_paths::interpose_library_name();
  const auto lib_path = w1::test_paths::interpose_library_path();
  HMODULE handle = LoadLibraryA(lib_path.c_str());
  REQUIRE(handle != nullptr);

  w1::monitor::module_event event{};
  void* loaded_base = nullptr;
  size_t loaded_size = 0;
  const auto saw_loaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::loaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_loaded);
  if (saw_loaded) {
    loaded_base = event.base;
    loaded_size = event.size;
    CHECK(loaded_base != nullptr);
    CHECK(loaded_size > 0);
  }

  FreeLibrary(handle);

  const auto saw_unloaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        if (e.type != w1::monitor::module_event::kind::unloaded) {
          return false;
        }
        if (loaded_base && e.base == loaded_base) {
          return true;
        }
        return !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_unloaded);
  if (saw_unloaded && loaded_base && event.base == loaded_base) {
    CHECK(event.size == loaded_size);
  }

  monitor->stop();
}

TEST_CASE("w1monitor windows thread monitor reports start/stop/rename") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  std::atomic<uint64_t> worker_tid{0};
  thread_name_params params{};
  params.tid_out = &worker_tid;
  params.name = L"w1mon_worker";
  params.sleep_ms = 50;

  DWORD thread_id = 0;
  HANDLE thread = CreateThread(nullptr, 0, thread_start_with_name, &params, 0, &thread_id);
  REQUIRE(thread != nullptr);

  while (worker_tid.load(std::memory_order_acquire) == 0) {
    std::this_thread::yield();
  }
  const uint64_t tid = worker_tid.load(std::memory_order_acquire);

  w1::monitor::thread_event event{};
  const auto saw_started = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::started && e.tid == tid;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_started);

  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  const bool has_set_description =
      kernel32 && GetProcAddress(kernel32, "SetThreadDescription") != nullptr;

  if (has_set_description) {
    const auto saw_rename = wait_for_event(
        *monitor, event,
        [&](const w1::monitor::thread_event& e) {
          return e.type == w1::monitor::thread_event::kind::renamed && e.tid == tid &&
                 e.name == "w1mon_worker";
        },
        std::chrono::milliseconds(1000));
    CHECK(saw_rename);
  }

  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);

  const auto saw_stopped = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::stopped && e.tid == tid;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_stopped);

  monitor->stop();
}

TEST_CASE("w1monitor windows thread monitor captures GetProcAddress thread start/stop") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  std::atomic<uint64_t> worker_tid{0};

  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  REQUIRE(kernel32 != nullptr);
  auto create_thread = reinterpret_cast<decltype(&CreateThread)>(GetProcAddress(kernel32, "CreateThread"));
  REQUIRE(create_thread != nullptr);

  DWORD thread_id = 0;
  HANDLE thread = create_thread(nullptr, 0, thread_start_record_tid, &worker_tid, 0, &thread_id);
  REQUIRE(thread != nullptr);

  while (worker_tid.load(std::memory_order_acquire) == 0) {
    std::this_thread::yield();
  }
  const uint64_t tid = worker_tid.load(std::memory_order_acquire);

  w1::monitor::thread_event event{};
  const auto saw_started = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::started && e.tid == tid;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_started);

  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);

  const auto saw_stopped = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::stopped && e.tid == tid;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_stopped);

  monitor->stop();
}

TEST_CASE("w1monitor windows thread monitor entry callback can override") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  std::atomic<bool> start_called{false};
  std::atomic<bool> callback_called{false};
  std::mutex capture_mutex;
  w1::monitor::thread_entry_context captured{};

  monitor->set_entry_callback([&](const w1::monitor::thread_entry_context& ctx, uint64_t& result) {
    {
      std::lock_guard<std::mutex> lock(capture_mutex);
      captured = ctx;
    }
    callback_called.store(true, std::memory_order_release);
    result = 0xBEEF;
    return true;
  });

  DWORD thread_id = 0;
  HANDLE thread = CreateThread(nullptr, 0, thread_start_set_flag, &start_called, 0, &thread_id);
  REQUIRE(thread != nullptr);

  WaitForSingleObject(thread, INFINITE);

  DWORD exit_code = 0;
  CHECK(GetExitCodeThread(thread, &exit_code));
  CloseHandle(thread);

  CHECK(callback_called.load(std::memory_order_acquire));
  CHECK_FALSE(start_called.load(std::memory_order_acquire));
  CHECK(exit_code == 0xBEEF);

  {
    std::lock_guard<std::mutex> lock(capture_mutex);
    CHECK(captured.kind == w1::monitor::thread_entry_kind::win32);
    CHECK(captured.tid == static_cast<uint64_t>(thread_id));
    CHECK(captured.start_routine == reinterpret_cast<void*>(&thread_start_set_flag));
    CHECK(captured.arg == &start_called);
  }

  monitor->stop();
}

#endif
