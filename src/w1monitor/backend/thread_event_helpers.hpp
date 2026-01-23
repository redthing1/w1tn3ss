#pragma once

#include <cstdint>
#include <string_view>

#include "w1monitor/event_queue.hpp"
#include "w1monitor/thread_monitor.hpp"

namespace w1::monitor::backend {

class thread_event_emitter {
public:
  explicit thread_event_emitter(event_queue& queue) : queue_(queue) {}

  void started(uint64_t tid) { push(thread_event::kind::started, tid, {}); }
  void stopped(uint64_t tid) { push(thread_event::kind::stopped, tid, {}); }
  void renamed(uint64_t tid, std::string_view name) { push(thread_event::kind::renamed, tid, name); }

private:
  void push(thread_event::kind kind, uint64_t tid, std::string_view name) {
    thread_event event{};
    event.type = kind;
    event.tid = tid;
    if (!name.empty()) {
      event.name.assign(name.begin(), name.end());
    }
    queue_.push(event);
  }

  event_queue& queue_;
};

class thread_stop_tracker {
public:
  void reset() { emitted_ = false; }
  bool should_emit() {
    if (emitted_) {
      return false;
    }
    emitted_ = true;
    return true;
  }

private:
  static thread_local bool emitted_;
};

inline thread_local bool thread_stop_tracker::emitted_ = false;

} // namespace w1::monitor::backend
