#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <QBDI.h>

#include "w1base/thread_utils.hpp"
#include "w1instrument/session_manager.hpp"
#include "w1runtime/process_monitor.hpp"

namespace w1::instrument {

template <tracer tracer_t> class process_tracer {
public:
  struct config {
    core::instrumentation_policy instrumentation{};
    QBDI::Options vm_options = QBDI::Options::NO_OPT;
    bool attach_new_threads = true;
    bool refresh_on_module_events = true;
    bool owns_monitor = true;
  };

  using session_type = trace_session<tracer_t>;
  using tracer_factory = std::function<tracer_t(const runtime::thread_info&)>;

  process_tracer(runtime::process_monitor& monitor, config cfg, tracer_factory factory)
      : monitor_(monitor), config_(std::move(cfg)),
        sessions_(build_base_config(), std::move(factory)) {
    callback_state_ = std::make_shared<callback_state>();
    callback_state_->owner = this;
  }

  process_tracer(const process_tracer&) = delete;
  process_tracer& operator=(const process_tracer&) = delete;
  process_tracer(process_tracer&&) = delete;
  process_tracer& operator=(process_tracer&&) = delete;

  ~process_tracer() { stop(); }

  void start() {
    if (started_.exchange(true, std::memory_order_acq_rel)) {
      return;
    }

    if (config_.owns_monitor && !monitor_.running()) {
      monitor_.start();
      started_monitor_ = true;
    }

    monitor_.modules().refresh();

    callback_state_->active.store(true, std::memory_order_release);
    auto weak_state = std::weak_ptr<callback_state>(callback_state_);

    if (subscription_id_ == 0) {
      subscription_id_ = monitor_.subscribe([weak_state](const runtime::monitor_event& event) {
        auto state = weak_state.lock();
        if (!state || !state->active.load(std::memory_order_acquire) || !state->owner) {
          return;
        }
        state->owner->handle_event(event);
      });
    }

    if (config_.attach_new_threads) {
      monitor_.set_thread_entry_callback([weak_state](const monitor::thread_entry_context& ctx, uint64_t& result_out) {
        auto state = weak_state.lock();
        if (!state || !state->active.load(std::memory_order_acquire) || !state->owner) {
          return false;
        }
        return state->owner->handle_thread_entry(ctx, result_out);
      });
    }
  }

  void stop() {
    if (!started_.exchange(false, std::memory_order_acq_rel)) {
      return;
    }

    callback_state_->active.store(false, std::memory_order_release);
    monitor_.set_thread_entry_callback({});

    if (subscription_id_ != 0) {
      monitor_.unsubscribe(subscription_id_);
      subscription_id_ = 0;
    }

    auto sessions = sessions_.take_all();
    for (auto& entry : sessions) {
      if (entry.second) {
        entry.second->shutdown();
      }
    }

    if (started_monitor_) {
      monitor_.stop();
      started_monitor_ = false;
    }
  }

  std::shared_ptr<session_type> attach_current_thread(std::string name = "main") {
    start();
    runtime::thread_info info{};
    info.tid = w1::util::current_thread_id();
    info.name = std::move(name);
    return sessions_.attach(info);
  }

  std::shared_ptr<session_type> attach_current_thread(QBDI::VM* vm, std::string name = "main") {
    start();

    runtime::thread_info info{};
    info.tid = w1::util::current_thread_id();
    info.name = std::move(name);
    return vm ? sessions_.attach(info, vm) : sessions_.attach(info);
  }

  bool run_main(QBDI::VM* vm, uint64_t start, uint64_t stop, std::string name = "main") {
    auto session = attach_current_thread(vm, std::move(name));
    if (!session) {
      return false;
    }

    const uint64_t tid = w1::util::current_thread_id();
    bool ok = session->run(start, stop);
    sessions_.detach(tid);
    return ok;
  }

private:
  struct callback_state {
    std::atomic<bool> active{false};
    process_tracer* owner = nullptr;
  };

  trace_session_config build_base_config() const {
    trace_session_config config{};
    config.instrumentation = config_.instrumentation;
    config.vm_options = config_.vm_options;
    config.shared_modules = &monitor_.modules();
    return config;
  }

  void handle_event(const runtime::monitor_event& event) {
    switch (event.type) {
      case runtime::monitor_event::kind::module_loaded:
      case runtime::monitor_event::kind::module_unloaded:
        if (config_.refresh_on_module_events) {
          sessions_.refresh_all();
        }
        break;
      case runtime::monitor_event::kind::thread_stopped:
        sessions_.detach(event.thread.tid);
        break;
      default:
        break;
    }
  }

  runtime::thread_info make_thread_info(uint64_t tid, const char* fallback_name) {
    runtime::thread_info info{};
    info.tid = tid;
    info.name = fallback_name ? fallback_name : "thread";
    if (const auto* existing = monitor_.threads().find(tid)) {
      info = *existing;
      if (info.name.empty()) {
        info.name = fallback_name ? fallback_name : "thread";
      }
    }
    return info;
  }

  bool handle_thread_entry(const monitor::thread_entry_context& ctx, uint64_t& result_out) {
    if (!ctx.start_routine) {
      return false;
    }

    auto info = make_thread_info(ctx.tid, "thread");
    auto session = sessions_.attach(info);
    if (!session) {
      return false;
    }

    if (!session->instrument()) {
      sessions_.detach(ctx.tid);
      return false;
    }

    std::vector<uint64_t> args(1, reinterpret_cast<uint64_t>(ctx.arg));
    uint64_t result = 0;
    session->call(reinterpret_cast<uint64_t>(ctx.start_routine), args, &result);
    result_out = result;

    sessions_.detach(ctx.tid);
    return true;
  }

  runtime::process_monitor& monitor_;
  config config_{};
  session_manager<tracer_t> sessions_;

  std::shared_ptr<callback_state> callback_state_{};
  std::atomic<bool> started_{false};
  bool started_monitor_ = false;
  runtime::process_monitor::subscription_id subscription_id_ = 0;
};

} // namespace w1::instrument
