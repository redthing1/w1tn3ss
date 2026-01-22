#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "w1monitor/monitor_factory.hpp"
#include "w1runtime/module_registry.hpp"
#include "w1runtime/monitor_event.hpp"
#include "w1runtime/thread_registry.hpp"

namespace w1::runtime {

class process_monitor {
public:
  using subscription_id = uint64_t;
  using event_callback = std::function<void(const monitor_event&)>;

  process_monitor();
  ~process_monitor();

  void start();
  void stop();
  void poll_once();

  subscription_id subscribe(event_callback callback);
  void unsubscribe(subscription_id id);
  void set_thread_entry_callback(w1::monitor::thread_entry_callback callback);

  module_registry& modules() { return modules_; }
  thread_registry& threads() { return threads_; }

  bool running() const { return running_.load(std::memory_order_acquire); }

private:
  void pump();
  void emit_event(const monitor_event& event);
  void handle_module_event(const w1::monitor::module_event& event);
  void handle_thread_event(const w1::monitor::thread_event& event);

  std::atomic<bool> running_{false};
  std::thread pump_thread_{};

  std::mutex callback_mutex_{};
  std::unordered_map<subscription_id, event_callback> callbacks_{};
  std::atomic<subscription_id> next_callback_id_{1};

  std::mutex monitor_mutex_{};
  std::unique_ptr<w1::monitor::module_monitor> module_monitor_{};
  std::unique_ptr<w1::monitor::thread_monitor> thread_monitor_{};
  w1::monitor::thread_entry_callback entry_callback_{};

  module_registry modules_{};
  thread_registry threads_{};
};

} // namespace w1::runtime
