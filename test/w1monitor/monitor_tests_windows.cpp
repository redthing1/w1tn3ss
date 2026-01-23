#if defined(_WIN32)

#include "doctest/doctest.hpp"

#include <atomic>
#include <chrono>
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

  monitor->stop();
}

TEST_CASE("w1monitor windows thread monitor reports start/stop/rename") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  std::atomic<uint64_t> worker_tid{0};
  auto thread_fn = [](LPVOID param) -> DWORD {
    auto* tid_ptr = static_cast<std::atomic<uint64_t>*>(param);
    tid_ptr->store(static_cast<uint64_t>(GetCurrentThreadId()), std::memory_order_release);
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
      auto set_desc = reinterpret_cast<HRESULT(WINAPI*)(HANDLE, PCWSTR)>(
          GetProcAddress(kernel32, "SetThreadDescription"));
      if (set_desc) {
        set_desc(GetCurrentThread(), L"w1mon_worker");
      }
    }
    Sleep(50);
    return 0;
  };

  DWORD thread_id = 0;
  HANDLE thread = CreateThread(nullptr, 0, thread_fn, &worker_tid, 0, &thread_id);
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
  auto thread_fn = [](LPVOID param) -> DWORD {
    auto* tid_ptr = static_cast<std::atomic<uint64_t>*>(param);
    tid_ptr->store(static_cast<uint64_t>(GetCurrentThreadId()), std::memory_order_release);
    Sleep(25);
    return 0;
  };

  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  REQUIRE(kernel32 != nullptr);
  auto create_thread = reinterpret_cast<decltype(&CreateThread)>(GetProcAddress(kernel32, "CreateThread"));
  REQUIRE(create_thread != nullptr);

  DWORD thread_id = 0;
  HANDLE thread = create_thread(nullptr, 0, thread_fn, &worker_tid, 0, &thread_id);
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

#endif
