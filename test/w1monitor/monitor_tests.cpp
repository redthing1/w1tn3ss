#include "doctest/doctest.hpp"

#include <atomic>
#include <chrono>
#include <thread>

#if defined(__APPLE__)
#include <dlfcn.h>
#include <pthread.h>
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
  const auto lib_path = w1::monitor::test_paths::test_library_path(lib_name);
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
    pthread_setname_np("w1monitor_worker");
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
               e.name == "w1monitor_worker";
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
