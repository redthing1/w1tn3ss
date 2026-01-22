#include "doctest/doctest.hpp"

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
