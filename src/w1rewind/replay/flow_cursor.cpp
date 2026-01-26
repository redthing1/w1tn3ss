#include "flow_cursor.hpp"

#include <algorithm>

namespace w1::rewind {

flow_cursor::flow_cursor(
    record_stream_cursor stream, flow_extractor extractor, history_window history, std::shared_ptr<trace_index> index
)
    : stream_(std::move(stream)), extractor_(std::move(extractor)), history_(std::move(history)),
      index_(std::move(index)) {
  history_size_ = static_cast<uint32_t>(history_.capacity());
}

void flow_cursor::set_observer(flow_record_observer* observer) { observer_ = observer; }

void flow_cursor::set_history_enabled(bool enabled) { history_enabled_ = enabled; }

void flow_cursor::set_history_size(uint32_t size) {
  history_size_ = size == 0 ? 1 : size;
  history_.resize(history_size_);
}

void flow_cursor::set_cancel_checker(std::function<bool()> checker) { cancel_checker_ = std::move(checker); }

void flow_cursor::clear_error() {
  error_.clear();
  error_kind_ = flow_error_kind::none;
}

void flow_cursor::set_error(flow_error_kind kind, const std::string& message) {
  error_ = message;
  error_kind_ = kind;
}

bool flow_cursor::check_cancel() {
  if (cancel_checker_ && cancel_checker_()) {
    set_error(flow_error_kind::other, "cancelled");
    return true;
  }
  return false;
}

void flow_cursor::reset_position_state() {
  history_.reset();
  current_step_ = flow_step{};
  has_position_ = false;
  clear_buffered_flow();
  stream_desynced_ = false;
}

void flow_cursor::clear_buffered_flow() { buffered_flow_.reset(); }

bool flow_cursor::uses_history_only() const { return history_enabled_ && observer_ == nullptr; }

bool flow_cursor::ensure_stream_synced() {
  if (!stream_desynced_) {
    return true;
  }
  if (history_.empty()) {
    stream_desynced_ = false;
    return true;
  }
  return seek_to_history(history_.current_index());
}

bool flow_cursor::open() {
  close();

  clear_error();

  std::string error;
  if (!stream_.open(error)) {
    set_error(flow_error_kind::other, error);
    return false;
  }
  if (!index_) {
    set_error(flow_error_kind::other, "trace index missing");
    return false;
  }
  if (!extractor_.context()) {
    set_error(flow_error_kind::other, "replay context missing");
    return false;
  }

  const auto& header = stream_.header();
  if (index_->header.trace_uuid != header.trace_uuid) {
    set_error(flow_error_kind::other, "trace index uuid mismatch");
    return false;
  }

  const auto& context = *extractor_.context();
  if (context.header.trace_uuid != header.trace_uuid) {
    set_error(flow_error_kind::other, "replay context trace uuid mismatch");
    return false;
  }

  bool can_blocks = context.features.has_block_exec && !context.blocks_by_id.empty();
  bool can_instructions = context.features.has_flow_instruction;
  if (can_blocks) {
    extractor_.set_flow_kind(flow_kind::blocks);
  } else if (can_instructions) {
    extractor_.set_flow_kind(flow_kind::instructions);
  } else {
    set_error(flow_error_kind::other, "trace has no flow records");
    return false;
  }

  open_ = true;
  return true;
}

void flow_cursor::close() {
  stream_.close();
  active_thread_id_ = 0;
  reset_position_state();
  open_ = false;
  clear_error();
}

bool flow_cursor::seek(uint64_t thread_id, uint64_t sequence) {
  clear_error();

  if (!open_) {
    set_error(flow_error_kind::other, "trace not open");
    return false;
  }
  if (!index_) {
    set_error(flow_error_kind::other, "trace index missing");
    return false;
  }
  if (thread_id == 0) {
    set_error(flow_error_kind::other, "thread not selected");
    return false;
  }

  active_thread_id_ = thread_id;
  reset_position_state();

  auto anchor = index_->find_anchor(thread_id, sequence);
  if (!anchor.has_value()) {
    set_error(flow_error_kind::other, "no anchor for thread");
    return false;
  }

  std::string error;
  if (!stream_.seek({anchor->chunk_index, anchor->record_offset}, error)) {
    set_error(flow_error_kind::other, error);
    return false;
  }

  return scan_until_sequence(thread_id, sequence);
}

bool flow_cursor::seek_from_location(uint64_t thread_id, uint64_t sequence, const trace_record_location& location) {
  clear_error();

  if (!open_) {
    set_error(flow_error_kind::other, "trace not open");
    return false;
  }
  if (thread_id == 0) {
    set_error(flow_error_kind::other, "thread not selected");
    return false;
  }

  active_thread_id_ = thread_id;
  reset_position_state();

  std::string error;
  if (!stream_.seek(location, error)) {
    set_error(flow_error_kind::other, error);
    return false;
  }

  return scan_until_sequence(thread_id, sequence);
}

bool flow_cursor::step_forward(flow_step& out, trace_record_location* location) {
  clear_error();

  if (!open_) {
    set_error(flow_error_kind::other, "trace not open");
    return false;
  }
  if (active_thread_id_ == 0) {
    set_error(flow_error_kind::other, "thread not selected");
    return false;
  }

  bool has_future = history_enabled_ && has_position_ && history_.has_future();

  if (has_future && uses_history_only()) {
    history_.forward();
    const auto& entry = history_.current();
    current_step_ = entry.step;
    has_position_ = true;
    out = entry.step;
    if (location) {
      *location = entry.location;
    }
    stream_desynced_ = true;
    return true;
  }

  if (!ensure_stream_synced()) {
    return false;
  }

  flow_step step{};
  trace_record_location loc{};
  if (!read_next_flow(step, &loc)) {
    return false;
  }

  if (has_future) {
    const auto& expected = history_.entry_at(history_.current_index() + 1);
    if (expected.step.thread_id != step.thread_id || expected.step.sequence != step.sequence) {
      set_error(flow_error_kind::other, "history mismatch");
      return false;
    }
    history_.forward();
    current_step_ = expected.step;
    has_position_ = true;
    out = expected.step;
    if (location) {
      *location = expected.location;
    }
  } else {
    if (observer_ != nullptr) {
      if (!consume_sequence_records(step.thread_id, step.sequence)) {
        return false;
      }
    }
    history_.push(step, loc);
    current_step_ = step;
    has_position_ = true;
    out = step;
    if (location) {
      *location = loc;
    }
    return true;
  }

  if (observer_ != nullptr) {
    if (!consume_sequence_records(step.thread_id, step.sequence)) {
      return false;
    }
  }

  return true;
}

bool flow_cursor::step_backward(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error(flow_error_kind::other, "trace not open");
    return false;
  }
  if (!has_position_) {
    set_error(flow_error_kind::other, "no current position");
    return false;
  }
  if (current_step_.sequence == 0) {
    set_error(flow_error_kind::begin_of_trace, "at start of trace");
    return false;
  }

  uint64_t target = current_step_.sequence - 1;

  if (!history_enabled_) {
    if (!seek(active_thread_id_, target)) {
      return false;
    }
    return step_forward(out);
  }

  if (!history_.empty() && history_.has_past()) {
    history_.rewind();
    const auto& entry = history_.current();
    if (uses_history_only()) {
      stream_desynced_ = true;
    } else {
      if (!seek_to_history(history_.current_index())) {
        return false;
      }
    }
    current_step_ = entry.step;
    has_position_ = true;
    out = entry.step;
    return true;
  }

  return prefill_history_window(target, out);
}

bool flow_cursor::scan_until_sequence(uint64_t thread_id, uint64_t sequence) {
  trace_record record;
  trace_record_location location{};

  while (true) {
    std::string error;
    if (!stream_.read_next(record, location, error)) {
      if (!error.empty()) {
        set_error(flow_error_kind::other, error);
      } else {
        set_error(flow_error_kind::end_of_trace, "end of trace");
      }
      return false;
    }
    if (check_cancel()) {
      return false;
    }
    bool is_flow = false;
    flow_step step{};
    if (!extractor_.try_extract(record, step, is_flow, error)) {
      set_error(flow_error_kind::other, error);
      return false;
    }

    if (!is_flow) {
      if (!extractor_.handle_non_flow(record, observer_, active_thread_id_, error)) {
        set_error(flow_error_kind::other, error);
        return false;
      }
      continue;
    }

    if (step.thread_id != thread_id) {
      continue;
    }
    if (step.sequence < sequence) {
      continue;
    }
    if (step.sequence > sequence) {
      set_error(flow_error_kind::other, "flow sequence not found");
      return false;
    }

    buffered_flow_ = buffered_flow{step, location};
    return true;
  }
}

bool flow_cursor::read_next_flow(flow_step& out, trace_record_location* location) {
  if (buffered_flow_.has_value()) {
    out = buffered_flow_->step;
    if (location) {
      *location = buffered_flow_->location;
    }
    buffered_flow_.reset();
    return true;
  }

  trace_record record;
  trace_record_location loc{};

  while (true) {
    std::string error;
    if (!stream_.read_next(record, loc, error)) {
      if (!error.empty()) {
        set_error(flow_error_kind::other, error);
      } else {
        set_error(flow_error_kind::end_of_trace, "end of trace");
      }
      return false;
    }
    if (check_cancel()) {
      return false;
    }
    bool is_flow = false;
    if (!extractor_.try_extract(record, out, is_flow, error)) {
      set_error(flow_error_kind::other, error);
      return false;
    }
    if (!is_flow) {
      if (!extractor_.handle_non_flow(record, observer_, active_thread_id_, error)) {
        set_error(flow_error_kind::other, error);
        return false;
      }
      continue;
    }
    if (out.thread_id != active_thread_id_) {
      continue;
    }
    if (location) {
      *location = loc;
    }
    return true;
  }
}

bool flow_cursor::consume_sequence_records(uint64_t thread_id, uint64_t sequence) {
  trace_record record;
  trace_record_location loc{};

  while (true) {
    std::string error;
    if (!stream_.read_next(record, loc, error)) {
      if (!error.empty()) {
        set_error(flow_error_kind::other, error);
        return false;
      }
      return true;
    }
    if (check_cancel()) {
      return false;
    }
    bool is_flow = false;
    flow_step step{};
    if (!extractor_.try_extract(record, step, is_flow, error)) {
      set_error(flow_error_kind::other, error);
      return false;
    }

    if (!is_flow) {
      if (!extractor_.handle_non_flow(record, observer_, active_thread_id_, error)) {
        set_error(flow_error_kind::other, error);
        return false;
      }
      continue;
    }

    if (step.thread_id != thread_id) {
      continue;
    }

    if (step.sequence <= sequence) {
      continue;
    }

    buffered_flow_ = buffered_flow{step, loc};
    return true;
  }
}

bool flow_cursor::seek_to_history(size_t index) {
  if (index >= history_.size()) {
    set_error(flow_error_kind::other, "history index out of range");
    return false;
  }

  const auto& entry = history_.entry_at(index);
  clear_buffered_flow();

  std::string error;
  if (!stream_.seek(entry.location, error)) {
    set_error(flow_error_kind::other, error);
    return false;
  }

  trace_record record;
  trace_record_location location{};
  if (!stream_.read_next(record, location, error)) {
    if (error.empty()) {
      error = "failed to read trace record";
    }
    set_error(flow_error_kind::other, error);
    return false;
  }

  stream_desynced_ = false;
  return true;
}

uint64_t flow_cursor::window_start_sequence(uint64_t target) const {
  if (history_size_ <= 1) {
    return target;
  }
  uint64_t window = static_cast<uint64_t>(history_size_);
  if (target + 1 <= window) {
    return 0;
  }
  return target + 1 - window;
}

bool flow_cursor::prefill_history_window(uint64_t target, flow_step& out) {
  uint64_t start = window_start_sequence(target);
  if (!seek(active_thread_id_, start)) {
    return false;
  }

  flow_step step{};
  trace_record_location loc{};
  while (true) {
    if (check_cancel()) {
      return false;
    }
    if (!ensure_stream_synced()) {
      return false;
    }
    if (!read_next_flow(step, &loc)) {
      return false;
    }
    if (observer_ != nullptr) {
      if (!consume_sequence_records(step.thread_id, step.sequence)) {
        return false;
      }
    }
    history_.push(step, loc);
    current_step_ = step;
    has_position_ = true;
    if (step.sequence == target) {
      out = step;
      return true;
    }
    if (step.sequence > target) {
      set_error(flow_error_kind::other, "flow sequence not found");
      return false;
    }
  }
}

} // namespace w1::rewind
