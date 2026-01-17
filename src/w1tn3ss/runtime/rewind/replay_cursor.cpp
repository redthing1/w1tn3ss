#include "replay_cursor.hpp"

#include <algorithm>

namespace w1::rewind {

namespace {

std::optional<uint16_t> find_register_id(const std::vector<std::string>& names, const std::string& target) {
  for (size_t i = 0; i < names.size(); ++i) {
    if (names[i] == target) {
      return static_cast<uint16_t>(i);
    }
  }
  return std::nullopt;
}

std::optional<uint16_t> resolve_stack_reg_id(trace_arch arch, const std::vector<std::string>& names) {
  switch (arch) {
  case trace_arch::x86_64:
    return find_register_id(names, "rsp");
  case trace_arch::x86:
    return find_register_id(names, "esp");
  case trace_arch::aarch64:
  case trace_arch::arm:
    return find_register_id(names, "sp");
  default:
    break;
  }
  auto candidate = find_register_id(names, "sp");
  if (candidate.has_value()) {
    return candidate;
  }
  candidate = find_register_id(names, "rsp");
  if (candidate.has_value()) {
    return candidate;
  }
  return find_register_id(names, "esp");
}

} // namespace

replay_cursor::replay_cursor(replay_cursor_config config)
    : config_(std::move(config)), cursor_({config_.trace_path, config_.index_path}) {
  if (config_.history_size == 0) {
    history_size_ = 1;
  } else {
    history_size_ = config_.history_size;
  }
  track_registers_ = config_.track_registers;
  track_memory_ = config_.track_memory;
}

bool replay_cursor::open() {
  close();

  if (!cursor_.open()) {
    error_ = cursor_.error();
    return false;
  }
  if (!cursor_.load_index()) {
    error_ = cursor_.error();
    return false;
  }

  const auto& header = cursor_.reader().header();
  bool use_blocks = (header.flags & trace_flag_blocks) != 0;
  bool use_instructions = (header.flags & trace_flag_instructions) != 0;

  if (use_blocks == use_instructions) {
    error_ = "trace has unsupported flow flags";
    return false;
  }

  flow_kind_ = use_blocks ? flow_kind::blocks : flow_kind::instructions;

  if (!load_metadata()) {
    return false;
  }

  open_ = true;
  return true;
}

void replay_cursor::close() {
  cursor_.close();
  modules_by_id_.clear();
  blocks_by_id_.clear();
  register_names_.clear();
  sp_reg_id_.reset();
  state_.reset();
  history_.clear();
  history_pos_ = 0;
  active_thread_id_ = 0;
  current_step_ = flow_step{};
  pending_flow_.reset();
  pending_location_.reset();
  has_position_ = false;
  open_ = false;
  error_.clear();
}

bool replay_cursor::seek(uint64_t thread_id, uint64_t sequence) {
  error_.clear();

  if (!open_) {
    error_ = "trace not open";
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
      state_.set_register_count(register_names_.size());
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
          error_ = cursor_.error();
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
    error_ = cursor_.error();
    return false;
  }

  return true;
}

bool replay_cursor::step_forward(flow_step& out) {
  error_.clear();

  if (!open_) {
    error_ = "trace not open";
    return false;
  }
  if (active_thread_id_ == 0) {
    error_ = "thread not selected";
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
      error_ = "history mismatch";
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

bool replay_cursor::step_backward(flow_step& out) {
  error_.clear();

  if (!open_) {
    error_ = "trace not open";
    return false;
  }
  if (!has_position_) {
    error_ = "no current position";
    return false;
  }
  if (current_step_.sequence == 0) {
    error_ = "at start of trace";
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
    error_ = "history empty";
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

bool replay_cursor::load_metadata() {
  modules_by_id_.clear();
  blocks_by_id_.clear();
  register_names_.clear();
  sp_reg_id_.reset();

  trace_reader reader(config_.trace_path);
  if (!reader.open()) {
    error_ = reader.error();
    return false;
  }

  bool need_blocks = (flow_kind_ == flow_kind::blocks);
  bool need_registers = track_registers_ || track_memory_;
  bool have_modules = false;
  bool have_registers = !need_registers;

  trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<register_table_record>(record)) {
      if (need_registers) {
        register_names_ = std::get<register_table_record>(record).names;
        have_registers = true;
      }
    } else if (std::holds_alternative<module_table_record>(record)) {
      const auto& modules = std::get<module_table_record>(record).modules;
      modules_by_id_.clear();
      for (const auto& module : modules) {
        modules_by_id_.emplace(module.id, module);
      }
      have_modules = true;
    } else if (need_blocks && std::holds_alternative<block_definition_record>(record)) {
      const auto& def = std::get<block_definition_record>(record);
      blocks_by_id_.emplace(def.block_id, def);
    }
  }

  if (!reader.error().empty()) {
    error_ = reader.error();
    return false;
  }

  if (!have_modules) {
    error_ = "module table missing";
    return false;
  }
  if (need_registers && !have_registers) {
    error_ = "register table missing";
    return false;
  }

  if (need_registers) {
    sp_reg_id_ = resolve_stack_reg_id(reader.header().architecture, register_names_);
  }

  if (track_registers_) {
    state_.set_register_count(register_names_.size());
  }

  return true;
}

bool replay_cursor::scan_until_sequence(uint64_t thread_id, uint64_t sequence) {
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
      error_ = "flow sequence not found";
      return false;
    }

    pending_flow_ = step;
    pending_location_ = location;
    return true;
  }

  if (!cursor_.error().empty()) {
    error_ = cursor_.error();
  } else {
    error_ = "end of trace";
  }
  return false;
}

bool replay_cursor::resolve_address(uint64_t module_id, uint64_t module_offset, uint64_t& address) {
  if (module_id == 0) {
    address = module_offset;
    return true;
  }
  auto it = modules_by_id_.find(module_id);
  if (it == modules_by_id_.end()) {
    error_ = "module id not found";
    return false;
  }
  address = it->second.base + module_offset;
  return true;
}

bool replay_cursor::try_parse_flow(const trace_record& record, flow_step& out, bool& is_flow) {
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
  auto it = blocks_by_id_.find(exec.block_id);
  if (it == blocks_by_id_.end()) {
    error_ = "block id not found";
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

bool replay_cursor::apply_state_record(const trace_record& record) {
  if (!(track_registers_ || track_memory_) || active_thread_id_ == 0) {
    return true;
  }

  if (std::holds_alternative<register_delta_record>(record)) {
    return apply_register_deltas(std::get<register_delta_record>(record));
  }
  if (std::holds_alternative<memory_access_record>(record)) {
    return apply_memory_access(std::get<memory_access_record>(record));
  }
  if (std::holds_alternative<boundary_record>(record)) {
    return apply_boundary_record(std::get<boundary_record>(record));
  }

  return true;
}

bool replay_cursor::apply_register_deltas(const register_delta_record& record) {
  if (!track_registers_) {
    return true;
  }
  if (record.thread_id != active_thread_id_) {
    return true;
  }
  state_.apply_register_deltas(record.deltas);
  return true;
}

bool replay_cursor::apply_memory_access(const memory_access_record& record) {
  if (!track_memory_) {
    return true;
  }
  if (record.thread_id != active_thread_id_) {
    return true;
  }
  if (!record.value_known || record.data.empty()) {
    return true;
  }
  if (record.kind != memory_access_kind::write) {
    return true;
  }
  state_.apply_memory_bytes(record.address, record.data);
  return true;
}

bool replay_cursor::apply_boundary_record(const boundary_record& record) {
  if (record.thread_id != active_thread_id_) {
    return true;
  }

  if (track_registers_) {
    state_.apply_register_snapshot(record.registers);
  }

  if (track_memory_ && !record.stack_window.empty()) {
    uint64_t sp = 0;
    bool have_sp = false;
    if (sp_reg_id_.has_value()) {
      if (track_registers_) {
        auto value = state_.register_value(*sp_reg_id_);
        if (value.has_value()) {
          sp = *value;
          have_sp = true;
        }
      }
      if (!have_sp) {
        auto value = read_register_value(record.registers, *sp_reg_id_);
        if (value.has_value()) {
          sp = *value;
          have_sp = true;
        }
      }
    }
    if (have_sp) {
      state_.apply_stack_window(sp, record.stack_window);
    }
  }

  return true;
}

std::optional<uint64_t> replay_cursor::read_register_value(
    const std::vector<register_delta>& regs,
    uint16_t reg_id
) const {
  for (const auto& reg : regs) {
    if (reg.reg_id == reg_id) {
      return reg.value;
    }
  }
  return std::nullopt;
}

bool replay_cursor::read_next_flow(flow_step& out, trace_record_location* location) {
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
    error_ = cursor_.error();
  } else {
    error_ = "end of trace";
  }
  return false;
}

bool replay_cursor::consume_sequence_records(uint64_t thread_id, uint64_t sequence) {
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
    error_ = cursor_.error();
    return false;
  }

  return true;
}

void replay_cursor::push_history(const flow_step& step, const trace_record_location& location) {
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

bool replay_cursor::seek_to_history(size_t index) {
  if (index >= history_.size()) {
    error_ = "history index out of range";
    return false;
  }

  const auto& entry = history_[index];
  if (!cursor_.seek_to_location(entry.location)) {
    error_ = cursor_.error();
    return false;
  }

  trace_record record;
  trace_record_location location{};
  if (!cursor_.read_next(record, &location)) {
    error_ = cursor_.error();
    return false;
  }

  return true;
}

} // namespace w1::rewind
