#include "history_window.hpp"

#include <algorithm>

namespace w1::rewind {

history_window::history_window(size_t capacity) { resize(capacity); }

void history_window::reset() {
  entries_.clear();
  current_index_ = 0;
}

void history_window::resize(size_t capacity) {
  capacity_ = std::max<size_t>(1, capacity);
  if (entries_.size() <= capacity_) {
    return;
  }

  size_t desired = capacity_;
  size_t current_index = current_index_;
  size_t remove_front = std::min(entries_.size() - desired, current_index);
  for (size_t i = 0; i < remove_front; ++i) {
    entries_.pop_front();
  }
  current_index -= remove_front;

  while (entries_.size() > desired) {
    entries_.pop_back();
  }

  if (entries_.empty()) {
    current_index_ = 0;
    return;
  }
  current_index_ = std::min(current_index, entries_.size() - 1);
}

const history_window::entry& history_window::current() const { return entries_[current_index_]; }

const history_window::entry& history_window::entry_at(size_t index) const { return entries_[index]; }

bool history_window::has_past() const { return !entries_.empty() && current_index_ > 0; }

bool history_window::has_future() const { return !entries_.empty() && current_index_ + 1 < entries_.size(); }

bool history_window::rewind() {
  if (!has_past()) {
    return false;
  }
  current_index_ -= 1;
  return true;
}

bool history_window::forward() {
  if (!has_future()) {
    return false;
  }
  current_index_ += 1;
  return true;
}

void history_window::push(const flow_step& step, const trace_record_location& location) {
  if (entries_.size() == capacity_) {
    entries_.pop_front();
    if (current_index_ > 0) {
      current_index_ -= 1;
    }
  }

  entries_.push_back(entry{step, location});
  current_index_ = entries_.size() - 1;
}

} // namespace w1::rewind
