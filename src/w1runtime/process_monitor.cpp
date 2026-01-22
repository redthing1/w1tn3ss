#include "w1runtime/process_monitor.hpp"

#include <chrono>

namespace w1::runtime {
namespace {
constexpr auto kPollInterval = std::chrono::milliseconds(5);
}

process_monitor::process_monitor() = default;

process_monitor::~process_monitor() { stop(); }

void process_monitor::start() {
  if (running_.exchange(true, std::memory_order_acq_rel)) {
    return;
  }

  {
    std::lock_guard<std::mutex> lock(monitor_mutex_);
    module_monitor_ = w1::monitor::make_module_monitor();
    thread_monitor_ = w1::monitor::make_thread_monitor();
    if (thread_monitor_) {
      thread_monitor_->set_entry_callback(entry_callback_);
    }
    if (module_monitor_) {
      module_monitor_->start();
    }
    if (thread_monitor_) {
      thread_monitor_->start();
    }
  }

  pump_thread_ = std::thread(&process_monitor::pump, this);
}

void process_monitor::stop() {
  if (!running_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }

  if (pump_thread_.joinable()) {
    pump_thread_.join();
  }

  std::lock_guard<std::mutex> lock(monitor_mutex_);
  if (module_monitor_) {
    module_monitor_->stop();
  }
  if (thread_monitor_) {
    thread_monitor_->stop();
  }
  module_monitor_.reset();
  thread_monitor_.reset();
}

void process_monitor::poll_once() {
  w1::monitor::module_event module_event{};
  w1::monitor::thread_event thread_event{};

  std::unique_lock<std::mutex> lock(monitor_mutex_);
  if (module_monitor_) {
    while (module_monitor_->poll(module_event)) {
      lock.unlock();
      handle_module_event(module_event);
      lock.lock();
    }
  }
  if (thread_monitor_) {
    while (thread_monitor_->poll(thread_event)) {
      lock.unlock();
      handle_thread_event(thread_event);
      lock.lock();
    }
  }
}

process_monitor::subscription_id process_monitor::subscribe(event_callback callback) {
  std::lock_guard<std::mutex> lock(callback_mutex_);
  subscription_id id = next_callback_id_.fetch_add(1, std::memory_order_relaxed);
  callbacks_.emplace(id, std::move(callback));
  return id;
}

void process_monitor::unsubscribe(subscription_id id) {
  std::lock_guard<std::mutex> lock(callback_mutex_);
  callbacks_.erase(id);
}

void process_monitor::set_thread_entry_callback(w1::monitor::thread_entry_callback callback) {
  std::lock_guard<std::mutex> lock(monitor_mutex_);
  entry_callback_ = std::move(callback);
  if (thread_monitor_) {
    thread_monitor_->set_entry_callback(entry_callback_);
  }
}

void process_monitor::pump() {
  while (running_.load(std::memory_order_acquire)) {
    poll_once();
    std::this_thread::sleep_for(kPollInterval);
  }
}

void process_monitor::emit_event(const monitor_event& event) {
  std::vector<event_callback> callbacks_copy;
  {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callbacks_copy.reserve(callbacks_.size());
    for (const auto& [id, callback] : callbacks_) {
      (void)id;
      callbacks_copy.push_back(callback);
    }
  }

  for (const auto& callback : callbacks_copy) {
    if (callback) {
      callback(event);
    }
  }
}

void process_monitor::handle_module_event(const w1::monitor::module_event& event) {
  modules_.refresh();

  monitor_event out{};
  out.module = event;
  out.type = (event.type == w1::monitor::module_event::kind::loaded)
                 ? monitor_event::kind::module_loaded
                 : monitor_event::kind::module_unloaded;
  emit_event(out);
}

void process_monitor::handle_thread_event(const w1::monitor::thread_event& event) {
  threads_.apply(event);

  monitor_event out{};
  out.thread = event;
  switch (event.type) {
    case w1::monitor::thread_event::kind::started:
      out.type = monitor_event::kind::thread_started;
      break;
    case w1::monitor::thread_event::kind::stopped:
      out.type = monitor_event::kind::thread_stopped;
      break;
    case w1::monitor::thread_event::kind::renamed:
      out.type = monitor_event::kind::thread_renamed;
      break;
    default:
      return;
  }
  emit_event(out);
}

} // namespace w1::runtime
