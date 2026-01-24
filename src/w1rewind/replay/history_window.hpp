#pragma once

#include <cstddef>
#include <deque>

#include "flow_types.hpp"
#include "w1rewind/trace/record_stream.hpp"

namespace w1::rewind {

class history_window {
public:
  struct entry {
    flow_step step;
    trace_record_location location;
  };

  explicit history_window(size_t capacity);

  void reset();
  void resize(size_t capacity);

  bool empty() const { return entries_.empty(); }
  size_t size() const { return entries_.size(); }
  size_t capacity() const { return capacity_; }
  size_t current_index() const { return current_index_; }

  const entry& current() const;
  const entry& entry_at(size_t index) const;

  bool has_past() const;
  bool has_future() const;
  bool rewind();
  bool forward();

  void push(const flow_step& step, const trace_record_location& location);

private:
  std::deque<entry> entries_;
  size_t current_index_ = 0;
  size_t capacity_ = 1;
};

} // namespace w1::rewind
