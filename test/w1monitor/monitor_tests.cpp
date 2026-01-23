#include "doctest/doctest.hpp"

#include "w1monitor/monitor_factory.hpp"

TEST_CASE("w1monitor factory returns monitors") {
  auto module_monitor = w1::monitor::make_module_monitor();
  auto thread_monitor = w1::monitor::make_thread_monitor();
  CHECK(module_monitor != nullptr);
  CHECK(thread_monitor != nullptr);
}
