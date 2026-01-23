#if defined(__linux__)

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "doctest/doctest.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "w1monitor/monitor_factory.hpp"
#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"
#include "monitor_test_helpers.hpp"
#include "test_paths.hpp"

namespace {

using w1::monitor::test::wait_for_event;

} // namespace

TEST_CASE("w1monitor linux module monitor reports load/unload") {
  auto monitor = w1::monitor::make_module_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  const char* lib_name = w1::test_paths::interpose_library_name();
  const auto lib_path = w1::test_paths::interpose_library_path();
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
