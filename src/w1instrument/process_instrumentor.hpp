#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <QBDI.h>

#include "w1base/thread_utils.hpp"
#include "w1instrument/session_pool.hpp"
#include "w1runtime/process_observer.hpp"

namespace w1::instrument {

template <tracer tracer_t> class process_instrumentor {
public:
  struct config {
    core::instrumentation_policy instrumentation{};
    QBDI::Options vm_options = QBDI::Options::NO_OPT;
    bool attach_new_threads = true;
    bool refresh_on_module_events = true;
    bool owns_observer = true;
    struct hooks {
      std::function<void(const runtime::process_event&)> on_event;
      std::function<void(const runtime::thread_info&)> on_thread_attach;
      std::function<void(const runtime::thread_info&)> on_thread_detach;
    } hooks{};
  };

  using session_type = vm_session<tracer_t>;
  using tracer_factory = std::function<tracer_t(const runtime::thread_info&)>;

  process_instrumentor(runtime::process_observer& observer, config cfg, tracer_factory factory)
      : observer_(observer), config_(std::move(cfg)),
        sessions_(build_base_config(), std::move(factory)) {
    callback_state_ = std::make_shared<callback_state>();
    callback_state_->owner = this;
  }

  process_instrumentor(const process_instrumentor&) = delete;
  process_instrumentor& operator=(const process_instrumentor&) = delete;
  process_instrumentor(process_instrumentor&&) = delete;
  process_instrumentor& operator=(process_instrumentor&&) = delete;

  ~process_instrumentor() { stop(); }

  void start() {
    if (started_.exchange(true, std::memory_order_acq_rel)) {
      return;
    }

    if (config_.owns_observer && !observer_.running()) {
      observer_.start();
      started_observer_ = true;
    }

    observer_.modules().refresh();

    callback_state_->active.store(true, std::memory_order_release);
    auto weak_state = std::weak_ptr<callback_state>(callback_state_);

    if (subscription_id_ == 0) {
      subscription_id_ = observer_.subscribe([weak_state](const runtime::process_event& event) {
        auto state = weak_state.lock();
        if (!state || !state->active.load(std::memory_order_acquire) || !state->owner) {
          return;
        }
        state->owner->handle_event(event);
      });
    }

    if (config_.attach_new_threads) {
      observer_.set_thread_entry_callback([weak_state](const monitor::thread_entry_context& ctx, uint64_t& result_out) {
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
    observer_.set_thread_entry_callback({});

    if (subscription_id_ != 0) {
      observer_.unsubscribe(subscription_id_);
      subscription_id_ = 0;
    }

    auto sessions = sessions_.take_all();
    for (auto& entry : sessions) {
      if (entry.second) {
        entry.second->shutdown();
      }
    }

    if (started_observer_) {
      observer_.stop();
      started_observer_ = false;
    }
  }

  std::shared_ptr<session_type> attach_current_thread(std::string name = "main") {
    start();
    runtime::thread_info info{};
    info.tid = w1::util::current_thread_id();
    info.name = std::move(name);
    auto session = sessions_.attach(info);
    if (session && config_.hooks.on_thread_attach) {
      config_.hooks.on_thread_attach(info);
    }
    return session;
  }

  std::shared_ptr<session_type> attach_current_thread(QBDI::VM* vm, std::string name = "main") {
    start();

    runtime::thread_info info{};
    info.tid = w1::util::current_thread_id();
    info.name = std::move(name);
    auto session = vm ? sessions_.attach(info, vm) : sessions_.attach(info);
    if (session && config_.hooks.on_thread_attach) {
      config_.hooks.on_thread_attach(info);
    }
    return session;
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
    process_instrumentor* owner = nullptr;
  };

  vm_session_config build_base_config() const {
    vm_session_config config{};
    config.instrumentation = config_.instrumentation;
    config.vm_options = config_.vm_options;
    config.shared_modules = &observer_.modules();
    return config;
  }

  void handle_event(const runtime::process_event& event) {
    if (config_.hooks.on_event) {
      config_.hooks.on_event(event);
    }
    switch (event.type) {
      case runtime::process_event::kind::module_loaded:
      case runtime::process_event::kind::module_unloaded:
        if (config_.refresh_on_module_events) {
          sessions_.refresh_all();
        }
        break;
      case runtime::process_event::kind::thread_stopped: {
        uint64_t tid = event.thread.tid;
        runtime::thread_info info = make_thread_info(tid, "thread");
        sessions_.detach(tid);
        if (config_.hooks.on_thread_detach) {
          config_.hooks.on_thread_detach(info);
        }
        break;
      }
      default:
        break;
    }
  }

  runtime::thread_info make_thread_info(uint64_t tid, const char* fallback_name) {
    runtime::thread_info info{};
    info.tid = tid;
    info.name = fallback_name ? fallback_name : "thread";
    if (const auto* existing = observer_.threads().find(tid)) {
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

    if (config_.hooks.on_thread_attach) {
      config_.hooks.on_thread_attach(info);
    }

    if (!session->instrument()) {
      sessions_.detach(ctx.tid);
      return false;
    }

    std::vector<uint64_t> args(1, reinterpret_cast<uint64_t>(ctx.arg));
    uint64_t result = 0;
    bool ok = session->call(reinterpret_cast<uint64_t>(ctx.start_routine), args, &result);

    sessions_.detach(ctx.tid);
    if (!ok) {
      return false;
    }

    result_out = result;
    return true;
  }

  runtime::process_observer& observer_;
  config config_{};
  session_pool<tracer_t> sessions_;

  std::shared_ptr<callback_state> callback_state_{};
  std::atomic<bool> started_{false};
  bool started_observer_ = false;
  runtime::process_observer::subscription_id subscription_id_ = 0;
};

} // namespace w1::instrument
