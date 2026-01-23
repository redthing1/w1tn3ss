#pragma once

#include <chrono>
#include <thread>

namespace w1::monitor::test {

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

} // namespace w1::monitor::test
