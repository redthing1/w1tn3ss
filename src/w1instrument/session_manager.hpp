#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

#include <QBDI.h>

#include "w1instrument/tracer/trace_session.hpp"
#include "w1runtime/thread_registry.hpp"

namespace w1::instrument {

template <tracer tracer_t> class session_manager {
public:
  using session_type = trace_session<tracer_t>;
  using tracer_factory = std::function<tracer_t(const runtime::thread_info&)>;

  session_manager(trace_session_config base_config, tracer_factory factory)
      : base_config_(std::move(base_config)), factory_(std::move(factory)) {}

  std::shared_ptr<session_type> attach(const runtime::thread_info& info, QBDI::VM* borrowed_vm = nullptr) {
    return attach(info.tid, info.name, borrowed_vm);
  }

  std::shared_ptr<session_type> attach(uint64_t tid, std::string name, QBDI::VM* borrowed_vm = nullptr) {
    if (tid == 0) {
      return {};
    }
    if (auto existing = find_session(tid)) {
      return existing;
    }

    runtime::thread_info info{};
    info.tid = tid;
    info.name = name.empty() ? "thread" : name;

    auto session = create_session(info, borrowed_vm);
    if (!session) {
      return {};
    }

    return insert_session(tid, std::move(session));
  }

  void detach(uint64_t tid) {
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
  }

  void refresh_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& entry : sessions_) {
      if (entry.second) {
        entry.second->request_refresh();
      }
    }
  }

  size_t count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
  }

  std::unordered_map<uint64_t, std::shared_ptr<session_type>> take_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_map<uint64_t, std::shared_ptr<session_type>> out;
    out.swap(sessions_);
    return out;
  }

private:
  std::shared_ptr<session_type> create_session(const runtime::thread_info& info, QBDI::VM* borrowed_vm) {
    if (!factory_) {
      return {};
    }

    trace_session_config config = base_config_;
    config.thread_id = info.tid;
    config.thread_name = info.name.empty() ? "thread" : info.name;

    tracer_t tracer_instance = factory_(info);
    if (borrowed_vm) {
      return std::make_shared<session_type>(config, std::move(tracer_instance), borrowed_vm);
    }
    return std::make_shared<session_type>(config, std::move(tracer_instance));
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

  trace_session_config base_config_{};
  tracer_factory factory_{};

  mutable std::mutex mutex_{};
  std::unordered_map<uint64_t, std::shared_ptr<session_type>> sessions_{};
};

} // namespace w1::instrument
