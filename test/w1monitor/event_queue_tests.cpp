#include "doctest/doctest.hpp"

#include <thread>

#include "w1monitor/event_queue.hpp"

TEST_CASE("w1monitor event_queue stores module events") {
  w1::monitor::event_queue queue;
  w1::monitor::module_event event{};
  event.type = w1::monitor::module_event::kind::loaded;
  event.path = "unit_test_module";
  event.base = reinterpret_cast<void*>(0x1234);
  event.size = 16;

  queue.push(event);

  w1::monitor::module_event out{};
  REQUIRE(queue.poll(out));
  CHECK(out.type == w1::monitor::module_event::kind::loaded);
  CHECK(out.path == "unit_test_module");
  CHECK(out.base == reinterpret_cast<void*>(0x1234));
  CHECK(out.size == 16);
  CHECK_FALSE(queue.poll(out));
}

TEST_CASE("w1monitor event_queue stores thread events") {
  w1::monitor::event_queue queue;
  w1::monitor::thread_event event{};
  event.type = w1::monitor::thread_event::kind::renamed;
  event.tid = 42;
  event.name = "worker";

  queue.push(event);

  w1::monitor::thread_event out{};
  REQUIRE(queue.poll(out));
  CHECK(out.type == w1::monitor::thread_event::kind::renamed);
  CHECK(out.tid == 42);
  CHECK(out.name == "worker");
  CHECK_FALSE(queue.poll(out));
}

TEST_CASE("w1monitor event_queue preserves FIFO order") {
  w1::monitor::event_queue queue;
  w1::monitor::module_event mod_a{};
  mod_a.type = w1::monitor::module_event::kind::loaded;
  mod_a.base = reinterpret_cast<void*>(0x1111);
  w1::monitor::module_event mod_b{};
  mod_b.type = w1::monitor::module_event::kind::unloaded;
  mod_b.base = reinterpret_cast<void*>(0x2222);

  queue.push(mod_a);
  queue.push(mod_b);

  w1::monitor::module_event out{};
  REQUIRE(queue.poll(out));
  CHECK(out.base == mod_a.base);
  REQUIRE(queue.poll(out));
  CHECK(out.base == mod_b.base);
}

TEST_CASE("w1monitor event_queue keeps module and thread events independent") {
  w1::monitor::event_queue queue;
  w1::monitor::module_event module{};
  module.type = w1::monitor::module_event::kind::loaded;
  module.base = reinterpret_cast<void*>(0x3333);
  w1::monitor::thread_event thread{};
  thread.type = w1::monitor::thread_event::kind::started;
  thread.tid = 77;

  queue.push(module);
  queue.push(thread);

  w1::monitor::module_event out_module{};
  w1::monitor::thread_event out_thread{};
  REQUIRE(queue.poll(out_module));
  CHECK(out_module.base == module.base);
  REQUIRE(queue.poll(out_thread));
  CHECK(out_thread.tid == thread.tid);
}

TEST_CASE("w1monitor event_queue clear removes queued events") {
  w1::monitor::event_queue queue;
  w1::monitor::module_event module{};
  module.type = w1::monitor::module_event::kind::loaded;
  module.base = reinterpret_cast<void*>(0x4444);
  w1::monitor::thread_event thread{};
  thread.type = w1::monitor::thread_event::kind::stopped;
  thread.tid = 88;

  queue.push(module);
  queue.push(thread);
  queue.clear();

  w1::monitor::module_event out_module{};
  w1::monitor::thread_event out_thread{};
  CHECK_FALSE(queue.poll(out_module));
  CHECK_FALSE(queue.poll(out_thread));
}

TEST_CASE("w1monitor event_queue supports concurrent pushes") {
  w1::monitor::event_queue queue;
  constexpr int kPerThread = 50;

  auto push_events = [&](int base_start) {
    for (int i = 0; i < kPerThread; ++i) {
      w1::monitor::module_event event{};
      event.type = w1::monitor::module_event::kind::loaded;
      event.base = reinterpret_cast<void*>(static_cast<uintptr_t>(base_start + i));
      queue.push(event);
    }
  };

  std::thread t1(push_events, 1000);
  std::thread t2(push_events, 2000);
  t1.join();
  t2.join();

  int count = 0;
  w1::monitor::module_event out{};
  while (queue.poll(out)) {
    ++count;
  }

  CHECK(count == kPerThread * 2);
}
