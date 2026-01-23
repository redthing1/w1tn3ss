#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "w1monitor/module_monitor.hpp"

namespace w1::monitor::backend {

struct module_snapshot_entry {
  void* base = nullptr;
  size_t size = 0;
  std::string path{};
};

class module_snapshot_tracker {
public:
  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    modules_.clear();
  }

  void seed(const std::vector<module_snapshot_entry>& modules) {
    refresh(modules, false, [](const module_event&) {});
  }

  template <typename EmitFn>
  void refresh(const std::vector<module_snapshot_entry>& modules, bool emit_events, EmitFn emit) {
    std::unordered_map<void*, module_snapshot_entry> next;
    next.reserve(modules.size());
    for (const auto& entry : modules) {
      if (!entry.base) {
        continue;
      }
      next[entry.base] = entry;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (emit_events) {
      for (const auto& [base, entry] : next) {
        if (modules_.find(base) == modules_.end()) {
          emit(make_event(module_event::kind::loaded, entry));
        }
      }
      for (const auto& [base, entry] : modules_) {
        if (next.find(base) == next.end()) {
          emit(make_event(module_event::kind::unloaded, entry));
        }
      }
    }

    modules_ = std::move(next);
  }

  void track(void* base, std::string path, size_t size) {
    if (!base) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto& entry = modules_[base];
    if (!entry.base) {
      entry.base = base;
    }
    if (!path.empty()) {
      entry.path = std::move(path);
    }
    if (size != 0) {
      entry.size = size;
    }
  }

  void untrack(void* base) {
    if (!base) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    modules_.erase(base);
  }

  bool fill_missing(module_event& event) const {
    if (!event.base) {
      return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = modules_.find(event.base);
    if (it == modules_.end()) {
      return false;
    }
    if (event.path.empty()) {
      event.path = it->second.path;
    }
    if (event.size == 0) {
      event.size = it->second.size;
    }
    return true;
  }

private:
  static module_event make_event(module_event::kind kind, const module_snapshot_entry& entry) {
    module_event event{};
    event.type = kind;
    event.path = entry.path;
    event.base = entry.base;
    event.size = entry.size;
    return event;
  }

  mutable std::mutex mutex_{};
  std::unordered_map<void*, module_snapshot_entry> modules_{};
};

} // namespace w1::monitor::backend
