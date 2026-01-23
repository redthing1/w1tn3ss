#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <QBDI.h>

#include "w1base/thread_utils.hpp"
#include "w1instrument/trace/thread_session.hpp"
#include "w1runtime/process_observer.hpp"

namespace w1::instrument {

template <tracer tracer_t>
class process_session {
public:
  struct hooks {
    std::function<void(const runtime::process_event&)> on_event;
    std::function<void(const runtime::thread_info&)> on_thread_attach;
    std::function<void(const runtime::thread_info&)> on_thread_detach;
  };

  struct config {
    core::instrumentation_policy instrumentation{};
    QBDI::Options vm_options = QBDI::Options::NO_OPT;
    bool attach_new_threads = true;
    bool refresh_on_module_events = true;
    bool owns_observer = true;
    hooks callbacks{};
  };

  using session_type = thread_session<tracer_t>;
  using tracer_factory = std::function<tracer_t(const runtime::thread_info&)>;

  process_session(runtime::process_observer& observer, config cfg, tracer_factory factory)
      : observer_(observer), config_(std::move(cfg)), factory_(std::move(factory)) {
    callback_state_ = std::make_shared<callback_state>();
    callback_state_->owner = this;
  }

  process_session(const process_session&) = delete;
  process_session& operator=(const process_session&) = delete;
  process_session(process_session&&) = delete;
  process_session& operator=(process_session&&) = delete;

  ~process_session() { stop(); }

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

    auto sessions = take_all_sessions();
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

  std::shared_ptr<session_type> attach_thread(const runtime::thread_info& info, QBDI::VM* borrowed_vm = nullptr) {
    start();
    auto session = attach_session(info, borrowed_vm);
    if (session && config_.callbacks.on_thread_attach) {
      config_.callbacks.on_thread_attach(info);
    }
    return session;
  }

  std::shared_ptr<session_type> attach_current_thread(std::string name = "main") {
    runtime::thread_info info{};
    info.tid = w1::util::current_thread_id();
    info.name = std::move(name);
    return attach_thread(info);
  }

  std::shared_ptr<session_type> attach_current_thread(QBDI::VM* vm, std::string name = "main") {
    runtime::thread_info info{};
    info.tid = w1::util::current_thread_id();
    info.name = std::move(name);
    return attach_thread(info, vm);
  }

  bool run_main(QBDI::VM* vm, uint64_t start, uint64_t stop, std::string name = "main") {
    auto session = attach_current_thread(vm, std::move(name));
    if (!session) {
      return false;
    }

    const uint64_t tid = w1::util::current_thread_id();
    bool ok = session->run(start, stop);
    detach_thread(tid);
    return ok;
  }

  bool call_current_thread(
      uint64_t function_ptr, const std::vector<uint64_t>& args, uint64_t* result = nullptr,
      std::string name = "main"
  ) {
    auto session = attach_current_thread(std::move(name));
    if (!session) {
      return false;
    }

    const uint64_t tid = w1::util::current_thread_id();
    bool ok = session->call(function_ptr, args, result);
    detach_thread(tid);
    return ok;
  }

  void detach_thread(uint64_t tid) {
    std::shared_ptr<session_type> session;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = sessions_.find(tid);
      if (it == sessions_.end()) {
        return;
      }
      session = std::move(it->second);
      sessions_.erase(it);
    }

    if (session) {
      session->shutdown();
    }

    if (config_.callbacks.on_thread_detach) {
      runtime::thread_info info = make_thread_info(tid, "thread");
      config_.callbacks.on_thread_detach(info);
    }
  }

  void refresh_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& entry : sessions_) {
      if (entry.second) {
        entry.second->request_refresh();
      }
    }
  }

  size_t session_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
  }

private:
  struct callback_state {
    std::atomic<bool> active{false};
    process_session* owner = nullptr;
  };

  thread_session_config build_base_config() const {
    thread_session_config config{};
    config.instrumentation = config_.instrumentation;
    config.vm_options = config_.vm_options;
    config.shared_modules = &observer_.modules();
    return config;
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

  std::shared_ptr<session_type> attach_session(const runtime::thread_info& info, QBDI::VM* borrowed_vm) {
    if (!factory_ || info.tid == 0) {
      return {};
    }

    if (auto existing = find_session(info.tid)) {
      return existing;
    }

    runtime::thread_info normalized = info;
    if (normalized.name.empty()) {
      normalized.name = "thread";
    }

    thread_session_config config = build_base_config();
    config.thread_id = normalized.tid;
    config.thread_name = normalized.name;

    tracer_t tracer_instance = factory_(normalized);
    std::shared_ptr<session_type> session;
    if (borrowed_vm) {
      session = std::make_shared<session_type>(config, std::move(tracer_instance), borrowed_vm);
    } else {
      session = std::make_shared<session_type>(config, std::move(tracer_instance));
    }

    return insert_session(normalized.tid, std::move(session));
  }

  std::shared_ptr<session_type> find_session(uint64_t tid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(tid);
    return it != sessions_.end() ? it->second : nullptr;
  }

  std::shared_ptr<session_type> insert_session(uint64_t tid, std::shared_ptr<session_type> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto [it, inserted] = sessions_.emplace(tid, std::move(session));
    return it->second;
  }

  std::unordered_map<uint64_t, std::shared_ptr<session_type>> take_all_sessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<uint64_t, std::shared_ptr<session_type>> out;
    out.swap(sessions_);
    return out;
  }

  void handle_event(const runtime::process_event& event) {
    if (config_.callbacks.on_event) {
      config_.callbacks.on_event(event);
    }

    switch (event.type) {
      case runtime::process_event::kind::module_loaded:
      case runtime::process_event::kind::module_unloaded:
        if (config_.refresh_on_module_events) {
          refresh_all();
        }
        break;
      case runtime::process_event::kind::thread_stopped:
        detach_thread(event.thread.tid);
        break;
      default:
        break;
    }
  }

  bool handle_thread_entry(const monitor::thread_entry_context& ctx, uint64_t& result_out) {
    if (!ctx.start_routine) {
      return false;
    }

    auto info = make_thread_info(ctx.tid, "thread");
    auto session = attach_session(info, nullptr);
    if (!session) {
      return false;
    }

    if (config_.callbacks.on_thread_attach) {
      config_.callbacks.on_thread_attach(info);
    }

    if (!session->instrument()) {
      detach_thread(ctx.tid);
      return false;
    }

    std::vector<uint64_t> args(1, reinterpret_cast<uint64_t>(ctx.arg));
    uint64_t result = 0;
    bool ok = session->call(reinterpret_cast<uint64_t>(ctx.start_routine), args, &result);

    detach_thread(ctx.tid);
    if (!ok) {
      return false;
    }

    result_out = result;
    return true;
  }

  runtime::process_observer& observer_;
  config config_{};
  tracer_factory factory_{};

  std::shared_ptr<callback_state> callback_state_{};
  std::atomic<bool> started_{false};
  bool started_observer_ = false;
  runtime::process_observer::subscription_id subscription_id_ = 0;

  mutable std::mutex mutex_{};
  std::unordered_map<uint64_t, std::shared_ptr<session_type>> sessions_{};
};

} // namespace w1::instrument
