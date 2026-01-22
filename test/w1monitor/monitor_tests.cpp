#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "doctest/doctest.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#if defined(__APPLE__)
#include <dlfcn.h>
#include <pthread.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include "w1monitor/monitor_factory.hpp"
#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"
#include "test_paths.hpp"

namespace {

template <typename Event, typename Monitor, typename Predicate>
bool wait_for_event(Monitor& monitor, Event& out, Predicate predicate, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    while (monitor.poll(out)) {
      if (predicate(out)) {
        return true;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return false;
}

} // namespace

TEST_CASE("w1monitor factory returns monitors") {
  auto module_monitor = w1::monitor::make_module_monitor();
  auto thread_monitor = w1::monitor::make_thread_monitor();
  CHECK(module_monitor != nullptr);
  CHECK(thread_monitor != nullptr);
}

#if defined(__APPLE__)
TEST_CASE("w1monitor darwin module monitor reports load/unload") {
  auto monitor = w1::monitor::make_module_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  const char* lib_name = "w1h00k_interpose_lib.dylib";
  const auto lib_path = w1::test_paths::test_library_path(lib_name);
  void* handle = dlopen(lib_path.c_str(), RTLD_NOW);
  REQUIRE(handle != nullptr);

  w1::monitor::module_event event{};
  const auto has_loaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::loaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(has_loaded);

  dlclose(handle);

  const auto has_unloaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::unloaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(has_unloaded);

  monitor->stop();
}

TEST_CASE("w1monitor darwin thread monitor reports start/stop/rename") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  std::atomic<uint64_t> worker_tid{0};
  std::atomic<bool> ready{false};

  std::thread worker([&]() {
    worker_tid.store(static_cast<uint64_t>(pthread_mach_thread_np(pthread_self())), std::memory_order_release);
    pthread_setname_np("w1mon_worker");
    ready.store(true, std::memory_order_release);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  });

  while (worker_tid.load(std::memory_order_acquire) == 0) {
    std::this_thread::yield();
  }

  w1::monitor::thread_event event{};
  const uint64_t tid = worker_tid.load(std::memory_order_acquire);

  const auto saw_started = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::started && e.tid == tid;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_started);

  const auto saw_rename = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::renamed && e.tid == tid &&
               e.name == "w1mon_worker";
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_rename);

  worker.join();

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

#if defined(__linux__)
TEST_CASE("w1monitor linux module monitor reports load/unload") {
  auto monitor = w1::monitor::make_module_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  const char* lib_name = "w1h00k_interpose_lib.so";
  const auto lib_path = w1::test_paths::test_library_path(lib_name);
  void* handle = dlopen(lib_path.c_str(), RTLD_NOW);
  REQUIRE(handle != nullptr);

  w1::monitor::module_event event{};
  const auto has_loaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::loaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(has_loaded);

  dlclose(handle);

  const auto has_unloaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::unloaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(has_unloaded);

  monitor->stop();
}

TEST_CASE("w1monitor linux thread monitor reports start/stop/rename") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  std::atomic<uint64_t> worker_tid{0};

  pthread_t thread{};
  auto start_fn = [](void* data) -> void* {
    auto* tid_ptr = static_cast<std::atomic<uint64_t>*>(data);
    const uint64_t tid = static_cast<uint64_t>(syscall(SYS_gettid));
    tid_ptr->store(tid, std::memory_order_release);
    pthread_setname_np(pthread_self(), "w1mon_worker");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return nullptr;
  };

  REQUIRE(pthread_create(&thread, nullptr, start_fn, &worker_tid) == 0);

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

  const auto saw_rename = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::renamed && e.tid == tid &&
               e.name == "w1mon_worker";
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_rename);

  pthread_join(thread, nullptr);

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

#if defined(_WIN32)
TEST_CASE("w1monitor windows module monitor reports load/unload") {
  auto monitor = w1::monitor::make_module_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  const char* lib_name = "w1h00k_interpose_lib.dll";
  const auto lib_path = w1::test_paths::test_library_path(lib_name);
  HMODULE handle = LoadLibraryA(lib_path.c_str());
  REQUIRE(handle != nullptr);

  w1::monitor::module_event event{};
  const auto saw_loaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::loaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000));
  CHECK(saw_loaded);

  FreeLibrary(handle);

  const auto saw_unloaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::unloaded &&
               !e.path.empty() && e.path.find(lib_name) != std::string::npos;
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
#endif
