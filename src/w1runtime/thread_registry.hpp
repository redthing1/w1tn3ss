#pragma once

#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1monitor/thread_monitor.hpp"

namespace w1::runtime {

struct thread_info {
  uint64_t tid = 0;
  std::string name{};
  bool alive = false;
};

class thread_registry {
public:
  void apply(const w1::monitor::thread_event& event);
  std::vector<thread_info> list_threads() const;
  const thread_info* find(uint64_t tid) const;

private:
  mutable std::shared_mutex mutex_{};
  std::unordered_map<uint64_t, thread_info> threads_{};
};

} // namespace w1::runtime
