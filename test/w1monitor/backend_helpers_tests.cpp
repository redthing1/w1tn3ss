#include "doctest/doctest.hpp"

#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "w1monitor/backend/module_snapshot.hpp"
#include "w1monitor/backend/thread_entry.hpp"
#include "w1monitor/backend/thread_event_helpers.hpp"

using w1::monitor::backend::module_snapshot_entry;
using w1::monitor::backend::module_snapshot_tracker;
using w1::monitor::backend::thread_event_emitter;
using w1::monitor::backend::thread_stop_tracker;
using w1::monitor::backend::dispatch_thread_entry;
using w1::monitor::event_queue;
using w1::monitor::module_event;
using w1::monitor::thread_entry_context;
using w1::monitor::thread_entry_kind;
using w1::monitor::thread_event;

TEST_CASE("w1monitor module_snapshot_tracker reports load/unload") {
  module_snapshot_tracker tracker;
  std::vector<module_snapshot_entry> initial{
      {reinterpret_cast<void*>(0x1000), 64, "a"},
      {reinterpret_cast<void*>(0x2000), 128, "b"},
  };
  tracker.seed(initial);

  std::vector<module_snapshot_entry> next{
      {reinterpret_cast<void*>(0x1000), 64, "a"},
      {reinterpret_cast<void*>(0x3000), 256, "c"},
  };

  bool saw_loaded = false;
  bool saw_unloaded = false;
  tracker.refresh(next, true, [&](const module_event& event) {
    if (event.type == module_event::kind::loaded && event.base == reinterpret_cast<void*>(0x3000)) {
      saw_loaded = true;
    }
    if (event.type == module_event::kind::unloaded && event.base == reinterpret_cast<void*>(0x2000)) {
      saw_unloaded = true;
    }
  });

  CHECK(saw_loaded);
  CHECK(saw_unloaded);
}

TEST_CASE("w1monitor module_snapshot_tracker respects emit flag") {
  module_snapshot_tracker tracker;
  std::vector<module_snapshot_entry> modules{
      {reinterpret_cast<void*>(0x1111), 64, "a"},
  };

  bool emitted = false;
  tracker.refresh(modules, false, [&](const module_event&) { emitted = true; });
  CHECK_FALSE(emitted);
}

TEST_CASE("w1monitor module_snapshot_tracker fills missing data") {
  module_snapshot_tracker tracker;
  tracker.track(reinterpret_cast<void*>(0x4000), "unit_test", 512);

  module_event event{};
  event.type = module_event::kind::loaded;
  event.base = reinterpret_cast<void*>(0x4000);

  REQUIRE(tracker.fill_missing(event));
  CHECK(event.path == "unit_test");
  CHECK(event.size == 512);

  module_event missing{};
  missing.type = module_event::kind::loaded;
  missing.base = reinterpret_cast<void*>(0x5000);
  CHECK_FALSE(tracker.fill_missing(missing));
}

TEST_CASE("w1monitor module_snapshot_tracker does not override set fields") {
  module_snapshot_tracker tracker;
  tracker.track(reinterpret_cast<void*>(0x6000), "tracked", 256);

  module_event event{};
  event.type = module_event::kind::loaded;
  event.base = reinterpret_cast<void*>(0x6000);
  event.path = "already_set";
  event.size = 128;

  REQUIRE(tracker.fill_missing(event));
  CHECK(event.path == "already_set");
  CHECK(event.size == 128);
}

TEST_CASE("w1monitor module_snapshot_tracker untrack removes entry") {
  module_snapshot_tracker tracker;
  tracker.track(reinterpret_cast<void*>(0x7000), "to_remove", 64);
  tracker.untrack(reinterpret_cast<void*>(0x7000));

  module_event event{};
  event.type = module_event::kind::loaded;
  event.base = reinterpret_cast<void*>(0x7000);
  CHECK_FALSE(tracker.fill_missing(event));
}

TEST_CASE("w1monitor thread_stop_tracker emits once per reset") {
  thread_stop_tracker tracker;
  CHECK(tracker.should_emit());
  CHECK_FALSE(tracker.should_emit());
  tracker.reset();
  CHECK(tracker.should_emit());
}

TEST_CASE("w1monitor thread_stop_tracker is thread local") {
  thread_stop_tracker tracker;
  tracker.reset();
  CHECK(tracker.should_emit());
  CHECK_FALSE(tracker.should_emit());

  bool other_thread_emitted = false;
  std::thread worker([&]() {
    other_thread_emitted = tracker.should_emit();
  });
  worker.join();

  CHECK(other_thread_emitted);
}

TEST_CASE("w1monitor thread_event_emitter enqueues events") {
  event_queue queue;
  thread_event_emitter emitter(queue);

  emitter.started(11);
  emitter.renamed(12, "worker");
  emitter.stopped(13);

  thread_event event{};
  REQUIRE(queue.poll(event));
  CHECK(event.type == thread_event::kind::started);
  CHECK(event.tid == 11);

  REQUIRE(queue.poll(event));
  CHECK(event.type == thread_event::kind::renamed);
  CHECK(event.tid == 12);
  CHECK(event.name == "worker");

  REQUIRE(queue.poll(event));
  CHECK(event.type == thread_event::kind::stopped);
  CHECK(event.tid == 13);
}

TEST_CASE("w1monitor dispatch_thread_entry honors callback") {
  thread_entry_context captured{};
  bool callback_called = false;
  int start_calls = 0;

  w1::monitor::thread_entry_callback callback = [&](const thread_entry_context& ctx, uint64_t& result) {
    callback_called = true;
    captured = ctx;
    result = 42;
    return true;
  };

  const uint64_t result = dispatch_thread_entry(
      callback,
      thread_entry_kind::posix,
      99,
      reinterpret_cast<void*>(0x1234),
      reinterpret_cast<void*>(0x5678),
      [&]() -> uint64_t {
        ++start_calls;
        return 7;
      });

  CHECK(callback_called);
  CHECK(start_calls == 0);
  CHECK(result == 42);
  CHECK(captured.kind == thread_entry_kind::posix);
  CHECK(captured.tid == 99);
  CHECK(captured.start_routine == reinterpret_cast<void*>(0x1234));
  CHECK(captured.arg == reinterpret_cast<void*>(0x5678));
}

TEST_CASE("w1monitor dispatch_thread_entry falls back when callback declines") {
  int start_calls = 0;

  w1::monitor::thread_entry_callback callback = [&](const thread_entry_context&, uint64_t& result) {
    result = 0;
    return false;
  };

  const uint64_t result = dispatch_thread_entry(
      callback,
      thread_entry_kind::win32,
      123,
      reinterpret_cast<void*>(0x1111),
      reinterpret_cast<void*>(0x2222),
      [&]() -> uint64_t {
        ++start_calls;
        return 99;
      });

  CHECK(start_calls == 1);
  CHECK(result == 99);
}

TEST_CASE("w1monitor dispatch_thread_entry invokes when no callback") {
  int start_calls = 0;
  w1::monitor::thread_entry_callback callback{};

  const uint64_t result = dispatch_thread_entry(
      callback,
      thread_entry_kind::posix,
      777,
      nullptr,
      nullptr,
      [&]() -> uint64_t {
        ++start_calls;
        return 1234;
      });

  CHECK(start_calls == 1);
  CHECK(result == 1234);
}
