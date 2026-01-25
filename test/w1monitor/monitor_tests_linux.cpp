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

using spawn_thread_fn = int (*)(pthread_t*, uint64_t*, const char*);
using join_thread_fn = int (*)(pthread_t);

constexpr uintptr_t kOverrideResult = 0x1234;

void* entry_callback_start(void* arg) {
  auto* ran_ptr = static_cast<std::atomic<bool>*>(arg);
  ran_ptr->store(true, std::memory_order_release);
  return reinterpret_cast<void*>(static_cast<uintptr_t>(0x7777));
}

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
        return e.type == w1::monitor::module_event::kind::loaded && !e.path.empty() &&
               e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(has_loaded);

  dlclose(handle);

  const auto has_unloaded = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::module_event& e) {
        return e.type == w1::monitor::module_event::kind::unloaded && !e.path.empty() &&
               e.path.find(lib_name) != std::string::npos;
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(has_unloaded);

  monitor->stop();
}

TEST_CASE("w1monitor linux thread entry callback can override start routine") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);

  std::atomic<bool> ran{false};
  std::atomic<int> observed_kind{-1};
  std::atomic<uint64_t> observed_tid{0};
  std::atomic<void*> observed_start{nullptr};
  std::atomic<void*> observed_arg{nullptr};

  monitor->set_entry_callback([&](const w1::monitor::thread_entry_context& ctx, uint64_t& result_out) {
    observed_kind.store(static_cast<int>(ctx.kind), std::memory_order_release);
    observed_tid.store(ctx.tid, std::memory_order_release);
    observed_start.store(ctx.start_routine, std::memory_order_release);
    observed_arg.store(ctx.arg, std::memory_order_release);
    result_out = static_cast<uint64_t>(kOverrideResult);
    return true;
  });

  monitor->start();

  pthread_t thread{};
  REQUIRE(pthread_create(&thread, nullptr, &entry_callback_start, &ran) == 0);

  void* thread_result = nullptr;
  pthread_join(thread, &thread_result);

  CHECK(thread_result == reinterpret_cast<void*>(kOverrideResult));
  CHECK(ran.load(std::memory_order_acquire) == false);
  CHECK(observed_kind.load(std::memory_order_acquire) == static_cast<int>(w1::monitor::thread_entry_kind::posix));
  CHECK(observed_tid.load(std::memory_order_acquire) != 0);
  CHECK(observed_start.load(std::memory_order_acquire) == reinterpret_cast<void*>(entry_callback_start));
  CHECK(observed_arg.load(std::memory_order_acquire) == &ran);

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
      std::chrono::milliseconds(1000)
  );
  CHECK(saw_started);

  const auto saw_rename = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::renamed && e.tid == tid && e.name == "w1mon_worker";
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(saw_rename);

  pthread_join(thread, nullptr);

  const auto saw_stopped = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::stopped && e.tid == tid;
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(saw_stopped);

  monitor->stop();
}

TEST_CASE("w1monitor linux thread monitor captures dlopen thread start/stop") {
  auto monitor = w1::monitor::make_thread_monitor();
  REQUIRE(monitor != nullptr);
  monitor->start();

  const auto lib_path = w1::test_paths::monitor_thread_library_path();
  REQUIRE(!lib_path.empty());

  void* handle = dlopen(lib_path.c_str(), RTLD_NOW);
  REQUIRE(handle != nullptr);

  auto spawn_thread = reinterpret_cast<spawn_thread_fn>(dlsym(handle, "w1monitor_spawn_thread"));
  auto join_thread = reinterpret_cast<join_thread_fn>(dlsym(handle, "w1monitor_join_thread"));
  REQUIRE(spawn_thread != nullptr);
  REQUIRE(join_thread != nullptr);

  pthread_t thread{};
  uint64_t tid = 0;
  REQUIRE(spawn_thread(&thread, &tid, "w1mon_plugin") == 0);
  REQUIRE(tid != 0);

  w1::monitor::thread_event event{};
  const auto saw_started = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::started && e.tid == tid;
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(saw_started);

  const auto saw_rename = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::renamed && e.tid == tid && e.name == "w1mon_plugin";
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(saw_rename);

  CHECK(join_thread(thread) == 0);

  const auto saw_stopped = wait_for_event(
      *monitor, event,
      [&](const w1::monitor::thread_event& e) {
        return e.type == w1::monitor::thread_event::kind::stopped && e.tid == tid;
      },
      std::chrono::milliseconds(1000)
  );
  CHECK(saw_stopped);

  dlclose(handle);
  monitor->stop();
}

#endif
