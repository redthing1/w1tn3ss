#pragma once

#include <deque>
#include <mutex>

#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"

namespace w1::monitor {

class event_queue {
public:
  void push(const module_event& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    module_events_.push_back(event);
  }

  void push(const thread_event& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    thread_events_.push_back(event);
  }

  bool poll(module_event& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (module_events_.empty()) {
      return false;
    }
    out = module_events_.front();
    module_events_.pop_front();
    return true;
  }

  bool poll(thread_event& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (thread_events_.empty()) {
      return false;
    }
    out = thread_events_.front();
    thread_events_.pop_front();
    return true;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    module_events_.clear();
    thread_events_.clear();
  }

private:
  std::mutex mutex_{};
  std::deque<module_event> module_events_{};
  std::deque<thread_event> thread_events_{};
};

} // namespace w1::monitor
