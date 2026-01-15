#pragma once

#include <sol/sol.hpp>

#include <mutex>
#include <vector>

namespace w1::tracers::script::runtime {

class callback_store {
public:
  size_t add(sol::protected_function callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.push_back(std::move(callback));
    return callbacks_.size() - 1;
  }

  sol::protected_function* get(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < callbacks_.size()) {
      return &callbacks_[index];
    }
    return nullptr;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.clear();
  }

private:
  std::mutex mutex_;
  std::vector<sol::protected_function> callbacks_;
};

} // namespace w1::tracers::script::runtime
