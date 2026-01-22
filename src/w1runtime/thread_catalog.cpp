#include "w1runtime/thread_catalog.hpp"

namespace w1::runtime {

void thread_catalog::apply(const w1::monitor::thread_event& event) {
  if (event.tid == 0) {
    return;
  }

  std::unique_lock lock(mutex_);
  auto& entry = threads_[event.tid];
  entry.tid = event.tid;

  switch (event.type) {
    case w1::monitor::thread_event::kind::started:
      entry.alive = true;
      break;
    case w1::monitor::thread_event::kind::stopped:
      entry.alive = false;
      break;
    case w1::monitor::thread_event::kind::renamed:
      entry.name = event.name;
      break;
    default:
      break;
  }
}

std::vector<thread_info> thread_catalog::list_threads() const {
  std::shared_lock lock(mutex_);
  std::vector<thread_info> result;
  result.reserve(threads_.size());
  for (const auto& [tid, info] : threads_) {
    result.push_back(info);
  }
  return result;
}

const thread_info* thread_catalog::find(uint64_t tid) const {
  std::shared_lock lock(mutex_);
  auto it = threads_.find(tid);
  if (it == threads_.end()) {
    return nullptr;
  }
  return &it->second;
}

} // namespace w1::runtime
