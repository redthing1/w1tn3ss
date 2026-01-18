#include "replay_flow_cursor.hpp"

#include <algorithm>
#include <unordered_map>

namespace w1::rewind {

replay_flow_cursor::replay_flow_cursor(replay_flow_cursor_config config)
    : config_(std::move(config)), cursor_({config_.trace_path, config_.index_path}) {
  history_size_ = config_.history_size == 0 ? 1 : config_.history_size;
  track_registers_ = config_.track_registers;
  track_memory_ = config_.track_memory;
  if (config_.context) {
    context_ = config_.context;
  }
}

void replay_flow_cursor::clear_error() {
  error_.clear();
  error_kind_ = replay_flow_error_kind::none;
}

void replay_flow_cursor::set_error(replay_flow_error_kind kind, const std::string& message) {
  error_ = message;
  error_kind_ = kind;
}

bool replay_flow_cursor::open() {
  close();

  if (!cursor_.open()) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }
  if (!cursor_.load_index()) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }

  const auto& header = cursor_.reader().header();
  bool use_blocks = (header.flags & trace_flag_blocks) != 0;
  bool use_instructions = (header.flags & trace_flag_instructions) != 0;

  if (use_blocks == use_instructions) {
    set_error(replay_flow_error_kind::other, "trace has unsupported flow flags");
    return false;
  }

  flow_kind_ = use_blocks ? flow_kind::blocks : flow_kind::instructions;

  if (!load_context()) {
    return false;
  }

  open_ = true;
  return true;
}

void replay_flow_cursor::close() {
  cursor_.close();
  owned_context_.reset();
  context_ = nullptr;
  state_applier_.reset();
  state_.reset();
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

bool replay_flow_cursor::seek(uint64_t thread_id, uint64_t sequence) {
  clear_error();

  if (!open_) {
    set_error(replay_flow_error_kind::other, "trace not open");
    return false;
  }

  active_thread_id_ = thread_id;
  history_.clear();
  history_pos_ = 0;
  has_position_ = false;
  current_step_ = flow_step{};
  pending_flow_.reset();
  pending_location_.reset();

  if (track_registers_ || track_memory_) {
    state_.reset();
    if (track_registers_) {
      state_.set_register_count(context_->register_names.size());
    }

    const trace_index* index = cursor_.index();
    if (index) {
      auto boundary = index->find_boundary(thread_id, sequence);
      if (boundary.has_value() && boundary->sequence == sequence) {
        if (sequence > 0) {
          boundary = index->find_boundary(thread_id, sequence - 1);
        } else {
          boundary.reset();
        }
      }
      if (boundary.has_value()) {
        if (!cursor_.seek_to_location({boundary->chunk_index, boundary->record_offset})) {
          set_error(replay_flow_error_kind::other, cursor_.error());
          return false;
        }
        if (!scan_until_sequence(thread_id, sequence)) {
          return false;
        }
        return true;
      }
    }
  }

  if (!cursor_.seek_flow(thread_id, sequence)) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }

  return true;
}

bool replay_flow_cursor::seek_with_checkpoint(const replay_checkpoint_entry& checkpoint, uint64_t sequence) {
  clear_error();

  if (!open_) {
    set_error(replay_flow_error_kind::other, "trace not open");
    return false;
  }
  if (checkpoint.thread_id == 0) {
    set_error(replay_flow_error_kind::other, "checkpoint missing thread id");
    return false;
  }
  if (checkpoint.sequence > sequence) {
    set_error(replay_flow_error_kind::other, "checkpoint beyond target sequence");
    return false;
  }

  active_thread_id_ = checkpoint.thread_id;
  history_.clear();
  history_pos_ = 0;
  has_position_ = false;
  current_step_ = flow_step{};
  pending_flow_.reset();
  pending_location_.reset();

  if (track_registers_ || track_memory_) {
    state_.reset();
    if (track_registers_) {
      state_.set_register_count(context_->register_names.size());
      state_.apply_register_snapshot(checkpoint.registers);
    }
    if (track_memory_) {
      std::unordered_map<uint64_t, uint8_t> memory;
      memory.reserve(checkpoint.memory.size());
      for (const auto& entry : checkpoint.memory) {
        memory.emplace(entry.first, entry.second);
      }
      state_.set_memory_map(std::move(memory));
    }
  }

  if (!cursor_.seek_to_location(checkpoint.location)) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }

  if (!scan_until_sequence(checkpoint.thread_id, sequence)) {
    return false;
  }

  return true;
}

bool replay_flow_cursor::step_forward(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error(replay_flow_error_kind::other, "trace not open");
    return false;
  }
  if (active_thread_id_ == 0) {
    set_error(replay_flow_error_kind::other, "thread not selected");
    return false;
  }

  flow_step step{};
  trace_record_location location{};

  bool use_history = !(track_registers_ || track_memory_);
  bool has_future = use_history && has_position_ && history_pos_ + 1 < history_.size();
  if (!read_next_flow(step, &location)) {
    return false;
  }

  if (has_future) {
    const auto& expected = history_[history_pos_ + 1];
    if (expected.step.thread_id != step.thread_id || expected.step.sequence != step.sequence) {
      set_error(replay_flow_error_kind::other, "history mismatch");
      return false;
    }
    history_pos_ += 1;
    current_step_ = expected.step;
    out = expected.step;
    return true;
  }

  if (track_registers_ || track_memory_) {
    if (!consume_sequence_records(step.thread_id, step.sequence)) {
      return false;
    }
  }

  push_history(step, location);
  current_step_ = step;
  has_position_ = true;
  out = step;
  return true;
}

bool replay_flow_cursor::step_backward(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error(replay_flow_error_kind::other, "trace not open");
    return false;
  }
  if (!has_position_) {
    set_error(replay_flow_error_kind::other, "no current position");
    return false;
  }
  if (current_step_.sequence == 0) {
    set_error(replay_flow_error_kind::begin_of_trace, "at start of trace");
    return false;
  }

  uint64_t target = current_step_.sequence - 1;
  if (track_registers_ || track_memory_) {
    if (!seek(active_thread_id_, target)) {
      return false;
    }
    return step_forward(out);
  }

  if (history_.empty()) {
    set_error(replay_flow_error_kind::other, "history empty");
    return false;
  }

  if (history_pos_ > 0) {
    history_pos_ -= 1;
    const auto& entry = history_[history_pos_];
    if (!seek_to_history(history_pos_)) {
      return false;
    }
    current_step_ = entry.step;
    out = entry.step;
    return true;
  }

  if (!seek(active_thread_id_, target)) {
    return false;
  }

  return step_forward(out);
}

bool replay_flow_cursor::load_context() {
  if (!context_) {
    replay_context loaded;
    if (!load_replay_context(config_.trace_path, loaded, error_)) {
      return false;
    }
    owned_context_ = std::move(loaded);
    context_ = &*owned_context_;
  }

  const auto& header = cursor_.reader().header();
  if (context_->header.version != header.version || context_->header.flags != header.flags ||
      context_->header.architecture != header.architecture || context_->header.pointer_size != header.pointer_size) {
    set_error(replay_flow_error_kind::other, "replay context header mismatch");
    return false;
  }

  if (context_->modules_by_id.empty()) {
    set_error(replay_flow_error_kind::other, "module table missing");
    return false;
  }
  if ((track_registers_ || track_memory_) && context_->register_names.empty()) {
    set_error(replay_flow_error_kind::other, "register table missing");
    return false;
  }
  if (flow_kind_ == flow_kind::blocks && context_->blocks_by_id.empty()) {
    set_error(replay_flow_error_kind::other, "block definitions missing");
    return false;
  }

  if (track_registers_ || track_memory_) {
    state_applier_.emplace(*context_);
  }

  if (track_registers_) {
    state_.set_register_count(context_->register_names.size());
  }

  return true;
}

bool replay_flow_cursor::scan_until_sequence(uint64_t thread_id, uint64_t sequence) {
  trace_record record;
  trace_record_location location{};

  while (cursor_.read_next(record, &location)) {
    bool is_flow = false;
    flow_step step{};
    if (!try_parse_flow(record, step, is_flow)) {
      return false;
    }

    if (!is_flow) {
      if (!apply_state_record(record)) {
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
      set_error(replay_flow_error_kind::other, "flow sequence not found");
      return false;
    }

    pending_flow_ = step;
    pending_location_ = location;
    return true;
  }

  if (!cursor_.error().empty()) {
    set_error(replay_flow_error_kind::other, cursor_.error());
  } else {
    set_error(replay_flow_error_kind::end_of_trace, "end of trace");
  }
  return false;
}

bool replay_flow_cursor::resolve_address(uint64_t module_id, uint64_t module_offset, uint64_t& address) {
  if (!context_->resolve_address(module_id, module_offset, address)) {
    set_error(replay_flow_error_kind::other, "module id not found");
    return false;
  }
  return true;
}

bool replay_flow_cursor::try_parse_flow(const trace_record& record, flow_step& out, bool& is_flow) {
  is_flow = false;
  if (flow_kind_ == flow_kind::instructions) {
    if (!std::holds_alternative<instruction_record>(record)) {
      return true;
    }
    const auto& inst = std::get<instruction_record>(record);
    out.thread_id = inst.thread_id;
    out.sequence = inst.sequence;
    out.module_id = inst.module_id;
    out.module_offset = inst.module_offset;
    out.size = inst.size;
    out.is_block = false;
    if (!resolve_address(out.module_id, out.module_offset, out.address)) {
      return false;
    }
    is_flow = true;
    return true;
  }

  if (!std::holds_alternative<block_exec_record>(record)) {
    return true;
  }

  const auto& exec = std::get<block_exec_record>(record);
  auto it = context_->blocks_by_id.find(exec.block_id);
  if (it == context_->blocks_by_id.end()) {
    set_error(replay_flow_error_kind::other, "block id not found");
    return false;
  }

  const auto& def = it->second;
  out.thread_id = exec.thread_id;
  out.sequence = exec.sequence;
  out.module_id = def.module_id;
  out.module_offset = def.module_offset;
  out.size = def.size;
  out.is_block = true;
  if (!resolve_address(out.module_id, out.module_offset, out.address)) {
    return false;
  }
  is_flow = true;
  return true;
}

bool replay_flow_cursor::apply_state_record(const trace_record& record) {
  if (!state_applier_.has_value()) {
    return true;
  }
  return state_applier_->apply_record(record, active_thread_id_, track_registers_, track_memory_, state_);
}

bool replay_flow_cursor::read_next_flow(flow_step& out, trace_record_location* location) {
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

  while (cursor_.read_next(record, &loc)) {
    bool is_flow = false;
    if (!try_parse_flow(record, out, is_flow)) {
      return false;
    }
    if (!is_flow) {
      if (!apply_state_record(record)) {
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

  if (!cursor_.error().empty()) {
    set_error(replay_flow_error_kind::other, cursor_.error());
  } else {
    set_error(replay_flow_error_kind::end_of_trace, "end of trace");
  }
  return false;
}

bool replay_flow_cursor::consume_sequence_records(uint64_t thread_id, uint64_t sequence) {
  trace_record record;
  trace_record_location loc{};

  while (cursor_.read_next(record, &loc)) {
    bool is_flow = false;
    flow_step step{};
    if (!try_parse_flow(record, step, is_flow)) {
      return false;
    }

    if (!is_flow) {
      if (!apply_state_record(record)) {
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

  if (!cursor_.error().empty()) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }

  return true;
}

void replay_flow_cursor::push_history(const flow_step& step, const trace_record_location& location) {
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

bool replay_flow_cursor::seek_to_history(size_t index) {
  if (index >= history_.size()) {
    set_error(replay_flow_error_kind::other, "history index out of range");
    return false;
  }

  const auto& entry = history_[index];
  if (!cursor_.seek_to_location(entry.location)) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }

  trace_record record;
  trace_record_location location{};
  if (!cursor_.read_next(record, &location)) {
    set_error(replay_flow_error_kind::other, cursor_.error());
    return false;
  }

  return true;
}

} // namespace w1::rewind
