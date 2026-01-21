#include "flow_cursor.hpp"

#include <algorithm>

namespace w1::rewind {

flow_cursor::flow_cursor(flow_cursor_config config)
    : config_(std::move(config)), stream_(config_.stream), index_(config_.index), context_(config_.context) {
  history_size_ = config_.history_size == 0 ? 1 : config_.history_size;
}

void flow_cursor::set_observer(flow_record_observer* observer) { observer_ = observer; }

void flow_cursor::set_history_enabled(bool enabled) { history_enabled_ = enabled; }

void flow_cursor::clear_error() {
  error_.clear();
  error_kind_ = flow_error_kind::none;
}

void flow_cursor::set_error(flow_error_kind kind, const std::string& message) {
  error_ = message;
  error_kind_ = kind;
}

bool flow_cursor::open() {
  close();

  if (!stream_) {
    set_error(flow_error_kind::other, "trace stream missing");
    return false;
  }
  if (!stream_->open()) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
    return false;
  }
  if (!index_) {
    set_error(flow_error_kind::other, "trace index missing");
    return false;
  }
  if (!context_) {
    set_error(flow_error_kind::other, "replay context missing");
    return false;
  }

  const auto& header = stream_->header();
  if (index_->header.trace_version != header.version) {
    set_error(flow_error_kind::other, "trace index version mismatch");
    return false;
  }
  if (index_->header.trace_flags != header.flags) {
    set_error(flow_error_kind::other, "trace index flags mismatch");
    return false;
  }
  if (index_->header.chunk_size != header.chunk_size) {
    set_error(flow_error_kind::other, "trace index chunk size mismatch");
    return false;
  }

  bool use_blocks = (header.flags & trace_flag_blocks) != 0;
  bool use_instructions = (header.flags & trace_flag_instructions) != 0;
  if (use_blocks == use_instructions) {
    set_error(flow_error_kind::other, "trace has unsupported flow flags");
    return false;
  }
  flow_kind_ = use_blocks ? flow_kind::blocks : flow_kind::instructions;

  if (context_->header.version != header.version || context_->header.flags != header.flags ||
      context_->header.arch != header.arch) {
    set_error(flow_error_kind::other, "replay context header mismatch");
    return false;
  }
  if (flow_kind_ == flow_kind::blocks && context_->blocks_by_id.empty()) {
    set_error(flow_error_kind::other, "block definitions missing");
    return false;
  }

  open_ = true;
  return true;
}

void flow_cursor::close() {
  if (stream_) {
    stream_->close();
  }
  history_.clear();
  history_pos_ = 0;
  active_thread_id_ = 0;
  current_step_ = flow_step{};
  pending_flow_.reset();
  pending_location_.reset();
  has_position_ = false;
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
  history_.clear();
  history_pos_ = 0;
  has_position_ = false;
  current_step_ = flow_step{};
  pending_flow_.reset();
  pending_location_.reset();

  auto anchor = index_->find_anchor(thread_id, sequence);
  if (!anchor.has_value()) {
    set_error(flow_error_kind::other, "no anchor for thread");
    return false;
  }

  if (!stream_->seek_to_location({anchor->chunk_index, anchor->record_offset})) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
    return false;
  }

  return scan_until_sequence(thread_id, sequence);
}

bool flow_cursor::seek_from_location(
    uint64_t thread_id, uint64_t sequence, const trace_record_location& location
) {
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
  history_.clear();
  history_pos_ = 0;
  has_position_ = false;
  current_step_ = flow_step{};
  pending_flow_.reset();
  pending_location_.reset();

  if (!stream_->seek_to_location(location)) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
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

  bool has_future = history_enabled_ && has_position_ && history_pos_ + 1 < history_.size();

  flow_step step{};
  trace_record_location loc{};
  if (!read_next_flow(step, &loc)) {
    return false;
  }

  if (has_future) {
    const auto& expected = history_[history_pos_ + 1];
    if (expected.step.thread_id != step.thread_id || expected.step.sequence != step.sequence) {
      set_error(flow_error_kind::other, "history mismatch");
      return false;
    }
    history_pos_ += 1;
    current_step_ = expected.step;
    has_position_ = true;
    out = expected.step;
    if (location) {
      *location = expected.location;
    }
    return true;
  }

  if (observer_ != nullptr) {
    if (!consume_sequence_records(step.thread_id, step.sequence)) {
      return false;
    }
  }

  push_history(step, loc);
  current_step_ = step;
  has_position_ = true;
  out = step;
  if (location) {
    *location = loc;
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

  if (history_.empty()) {
    set_error(flow_error_kind::other, "history empty");
    return false;
  }

  if (history_pos_ > 0) {
    history_pos_ -= 1;
    const auto& entry = history_[history_pos_];
    if (!seek_to_history(history_pos_)) {
      return false;
    }
    current_step_ = entry.step;
    has_position_ = true;
    out = entry.step;
    return true;
  }

  if (!seek(active_thread_id_, target)) {
    return false;
  }
  return step_forward(out);
}

bool flow_cursor::scan_until_sequence(uint64_t thread_id, uint64_t sequence) {
  trace_record record;
  trace_record_location location{};

  while (stream_->read_next(record, &location)) {
    bool is_flow = false;
    flow_step step{};
    if (!try_parse_flow(record, step, is_flow)) {
      return false;
    }

    if (!is_flow) {
      if (!handle_non_flow(record)) {
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

    pending_flow_ = step;
    pending_location_ = location;
    return true;
  }

  if (!stream_->error().empty()) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
  } else {
    set_error(flow_error_kind::end_of_trace, "end of trace");
  }
  return false;
}

bool flow_cursor::try_parse_flow(const trace_record& record, flow_step& out, bool& is_flow) {
  is_flow = false;
  if (flow_kind_ == flow_kind::instructions) {
    if (!std::holds_alternative<instruction_record>(record)) {
      return true;
    }
    const auto& inst = std::get<instruction_record>(record);
    out.thread_id = inst.thread_id;
    out.sequence = inst.sequence;
    out.size = inst.size;
    out.address = inst.address;
    out.block_id = 0;
    out.flags = inst.flags;
    out.is_block = false;
    is_flow = true;
    return true;
  }

  if (!std::holds_alternative<block_exec_record>(record)) {
    return true;
  }

  const auto& exec = std::get<block_exec_record>(record);
  auto it = context_->blocks_by_id.find(exec.block_id);
  if (it == context_->blocks_by_id.end()) {
    set_error(flow_error_kind::other, "block id not found");
    return false;
  }

  const auto& def = it->second;
  out.thread_id = exec.thread_id;
  out.sequence = exec.sequence;
  out.size = def.size;
  out.address = def.address;
  out.block_id = exec.block_id;
  out.flags = def.flags;
  out.is_block = true;
  is_flow = true;
  return true;
}

bool flow_cursor::read_next_flow(flow_step& out, trace_record_location* location) {
  if (pending_flow_.has_value()) {
    out = *pending_flow_;
    pending_flow_.reset();
    if (location && pending_location_.has_value()) {
      *location = *pending_location_;
    }
    pending_location_.reset();
    return true;
  }

  trace_record record;
  trace_record_location loc{};

  while (stream_->read_next(record, &loc)) {
    bool is_flow = false;
    if (!try_parse_flow(record, out, is_flow)) {
      return false;
    }
    if (!is_flow) {
      if (!handle_non_flow(record)) {
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

  if (!stream_->error().empty()) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
  } else {
    set_error(flow_error_kind::end_of_trace, "end of trace");
  }
  return false;
}

bool flow_cursor::consume_sequence_records(uint64_t thread_id, uint64_t sequence) {
  trace_record record;
  trace_record_location loc{};

  while (stream_->read_next(record, &loc)) {
    bool is_flow = false;
    flow_step step{};
    if (!try_parse_flow(record, step, is_flow)) {
      return false;
    }

    if (!is_flow) {
      if (!handle_non_flow(record)) {
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

    pending_flow_ = step;
    pending_location_ = loc;
    return true;
  }

  if (!stream_->error().empty()) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
    return false;
  }

  return true;
}

bool flow_cursor::handle_non_flow(const trace_record& record) {
  if (!observer_) {
    return true;
  }
  std::string observer_error;
  if (!observer_->on_record(record, active_thread_id_, observer_error)) {
    if (observer_error.empty()) {
      observer_error = "failed to apply trace record";
    }
    set_error(flow_error_kind::other, observer_error);
    return false;
  }
  return true;
}

void flow_cursor::push_history(const flow_step& step, const trace_record_location& location) {
  if (history_.size() == history_size_) {
    history_.pop_front();
    if (history_pos_ > 0) {
      history_pos_ -= 1;
    }
  }

  history_.push_back(history_entry{step, location});
  history_pos_ = history_.size() - 1;
  has_position_ = true;
}

bool flow_cursor::seek_to_history(size_t index) {
  if (index >= history_.size()) {
    set_error(flow_error_kind::other, "history index out of range");
    return false;
  }

  const auto& entry = history_[index];
  if (!stream_->seek_to_location(entry.location)) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
    return false;
  }

  trace_record record;
  trace_record_location location{};
  if (!stream_->read_next(record, &location)) {
    set_error(flow_error_kind::other, std::string(stream_->error()));
    return false;
  }

  return true;
}

} // namespace w1::rewind
