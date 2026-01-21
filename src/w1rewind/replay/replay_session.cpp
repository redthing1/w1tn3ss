#include "replay_session.hpp"

#include <cstddef>

namespace w1::rewind {

namespace {

std::vector<std::optional<uint64_t>> build_unknown_registers(size_t count) {
  return std::vector<std::optional<uint64_t>>(count, std::nullopt);
}

memory_read build_unknown_memory(size_t count) {
  memory_read out;
  out.bytes.assign(count, std::byte{0});
  out.known.assign(count, 0);
  return out;
}

replay_session::replay_error_kind map_flow_error_kind(flow_error_kind kind) {
  switch (kind) {
  case flow_error_kind::begin_of_trace:
    return replay_session::replay_error_kind::begin_of_trace;
  case flow_error_kind::end_of_trace:
    return replay_session::replay_error_kind::end_of_trace;
  case flow_error_kind::none:
    return replay_session::replay_error_kind::none;
  default:
    return replay_session::replay_error_kind::other;
  }
}

} // namespace

replay_session::replay_session(replay_session_config config) : config_(std::move(config)) {
  block_decoder_ = config_.block_decoder;
}

bool replay_session::open() {
  close();
  clear_error();

  if (!config_.stream) {
    set_error("trace stream required");
    return false;
  }
  if (!config_.index) {
    set_error("trace index required");
    return false;
  }
  if (config_.context.header.version == 0) {
    set_error("replay context required");
    return false;
  }

  context_ = config_.context;
  block_decoder_ = config_.block_decoder;

  if (config_.track_registers && context_.register_specs.empty() &&
      (context_.header.flags & trace_flag_register_deltas) != 0) {
    set_error("register specs missing");
    return false;
  }

  state_applier_.emplace(context_);
  flow_cursor_config cursor_config{};
  cursor_config.stream = config_.stream;
  cursor_config.index = config_.index;
  cursor_config.history_size = config_.history_size;
  cursor_config.context = &context_;
  flow_cursor_.emplace(std::move(cursor_config));
  if (!flow_cursor_->open()) {
    set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
    return false;
  }

  stateful_flow_cursor_.emplace(*flow_cursor_, *state_applier_, state_);
  stateful_flow_cursor_->configure(context_, config_.track_registers, config_.track_memory);
  instruction_cursor_.emplace(*stateful_flow_cursor_);
  instruction_cursor_->set_decoder(block_decoder_);

  if (config_.checkpoint) {
    checkpoint_index_ = config_.checkpoint;
    if (!validate_checkpoint(*checkpoint_index_)) {
      return false;
    }
  }

  open_ = true;

  if (config_.thread_id != 0) {
    if (!select_thread(config_.thread_id, config_.start_sequence)) {
      return false;
    }
  }

  return true;
}

void replay_session::close() {
  flow_cursor_.reset();
  stateful_flow_cursor_.reset();
  state_applier_.reset();
  instruction_cursor_.reset();
  context_ = replay_context{};
  state_.reset();
  current_step_ = flow_step{};
  active_thread_id_ = 0;
  checkpoint_index_.reset();
  notice_.reset();
  open_ = false;
  has_position_ = false;
  clear_error();
}

bool replay_session::select_thread(uint64_t thread_id, uint64_t sequence) {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!flow_cursor_.has_value()) {
    set_error("flow cursor not ready");
    return false;
  }
  if (!stateful_flow_cursor_.has_value()) {
    set_error("stateful flow cursor not ready");
    return false;
  }

  stateful_flow_cursor_->configure(context_, config_.track_registers, config_.track_memory);

  bool used_checkpoint = false;
  if (checkpoint_index_ && (config_.track_registers || config_.track_memory)) {
    const auto* checkpoint = find_checkpoint(thread_id, sequence);
    if (checkpoint) {
      if (!apply_checkpoint(*checkpoint)) {
        return false;
      }
      if (!flow_cursor_->seek_from_location(thread_id, sequence, checkpoint->location)) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
        return false;
      }
      used_checkpoint = true;
    }
  }

  bool used_snapshot = false;
  if (!used_checkpoint && (config_.track_registers || config_.track_memory) && config_.index) {
    auto snapshot = config_.index->find_snapshot(thread_id, sequence);
    if (snapshot.has_value() && snapshot->sequence == sequence) {
      if (sequence > 0) {
        snapshot = config_.index->find_snapshot(thread_id, sequence - 1);
      } else {
        snapshot.reset();
      }
    }
    if (snapshot.has_value()) {
      if (!flow_cursor_->seek_from_location(thread_id, sequence, {snapshot->chunk_index, snapshot->record_offset})) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
        return false;
      }
      used_snapshot = true;
    }
  }

  if (!used_checkpoint && !used_snapshot) {
    if (!flow_cursor_->seek(thread_id, sequence)) {
      set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
      return false;
    }
  }

  active_thread_id_ = thread_id;
  reset_instruction_cursor();
  has_position_ = false;
  current_step_ = flow_step{};
  return true;
}

bool replay_session::step_flow() {
  flow_step step{};
  if (!step_flow_internal(step)) {
    return false;
  }

  reset_instruction_cursor();
  if (instruction_cursor_.has_value()) {
    instruction_cursor_->sync_with_flow_step(step);
  }
  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::step_backward() {
  reset_instruction_cursor();

  flow_step step{};
  if (!step_flow_backward_internal(step)) {
    return false;
  }

  if (instruction_cursor_.has_value()) {
    instruction_cursor_->sync_with_flow_step(step);
  }
  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::step_instruction() {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!instruction_cursor_.has_value()) {
    set_error("instruction cursor not ready");
    return false;
  }

  flow_step step{};
  if (!instruction_cursor_->step_forward(step)) {
    auto kind = replay_error_kind::other;
    if (flow_cursor_.has_value()) {
      auto mapped = map_flow_error_kind(flow_cursor_->error_kind());
      kind = mapped == replay_error_kind::none ? replay_error_kind::other : mapped;
    }
    set_error(kind, instruction_cursor_->error());
    return false;
  }

  if (auto notice = instruction_cursor_->take_notice(); notice.has_value()) {
    notice_ = notice;
  }

  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::step_instruction_backward() {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!instruction_cursor_.has_value()) {
    set_error("instruction cursor not ready");
    return false;
  }
  if (!has_position_) {
    set_error("no current position");
    return false;
  }

  flow_step step{};
  if (!instruction_cursor_->step_backward(step)) {
    auto kind = replay_error_kind::other;
    if (flow_cursor_.has_value()) {
      auto mapped = map_flow_error_kind(flow_cursor_->error_kind());
      kind = mapped == replay_error_kind::none ? replay_error_kind::other : mapped;
    }
    set_error(kind, instruction_cursor_->error());
    return false;
  }

  if (auto notice = instruction_cursor_->take_notice(); notice.has_value()) {
    notice_ = notice;
  }

  current_step_ = step;
  has_position_ = true;
  return true;
}

bool replay_session::sync_instruction_position() {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!instruction_cursor_.has_value()) {
    set_error("instruction cursor not ready");
    return false;
  }
  if (!has_position_) {
    set_error("no current position");
    return false;
  }

  instruction_cursor_->set_position(current_step_);
  if (auto notice = instruction_cursor_->take_notice(); notice.has_value()) {
    notice_ = notice;
  }
  current_step_ = instruction_cursor_->current_step();
  has_position_ = instruction_cursor_->has_position();
  return true;
}

std::vector<std::optional<uint64_t>> replay_session::read_registers() const {
  const size_t count = context_.register_specs.size();
  if (!config_.track_registers || !stateful_flow_cursor_.has_value()) {
    return build_unknown_registers(count);
  }
  const auto& regs = state_.registers();
  if (regs.size() == count) {
    return regs;
  }

  auto out = build_unknown_registers(count);
  size_t copy_count = std::min(out.size(), regs.size());
  for (size_t i = 0; i < copy_count; ++i) {
    out[i] = regs[i];
  }
  return out;
}

bool replay_session::read_register_bytes(uint16_t reg_id, std::span<std::byte> out, bool& known) const {
  known = false;
  if (!config_.track_registers || !stateful_flow_cursor_.has_value()) {
    return true;
  }
  if (reg_id >= context_.register_specs.size()) {
    return false;
  }
  const auto& spec = context_.register_specs[reg_id];
  if (spec.value_kind != register_value_kind::bytes) {
    return false;
  }
  size_t size = (spec.bits + 7u) / 8u;
  if (size == 0 || out.size() < size) {
    return false;
  }
  return state_.copy_register_bytes(reg_id, out, known);
}

memory_read replay_session::read_memory(uint64_t address, size_t size) const {
  if (!config_.track_memory || !stateful_flow_cursor_.has_value()) {
    return build_unknown_memory(size);
  }
  return state_.read_memory(address, size);
}

const replay_state* replay_session::state() const {
  if (!stateful_flow_cursor_.has_value() || (!config_.track_registers && !config_.track_memory)) {
    return nullptr;
  }
  return &state_;
}

bool replay_session::apply_checkpoint(const replay_checkpoint_entry& checkpoint) {
  state_.reset();
  if (config_.track_registers) {
    state_.set_register_specs(context_.register_specs);
    state_.apply_register_snapshot(checkpoint.registers);
    if (!checkpoint.register_bytes_entries.empty()) {
      if (!state_.apply_register_bytes(checkpoint.register_bytes_entries, checkpoint.register_bytes)) {
        set_error("checkpoint register bytes mismatch");
        return false;
      }
    }
  }
  if (config_.track_memory) {
    state_.set_memory_spans(checkpoint.memory);
  }
  return true;
}

bool replay_session::validate_checkpoint(const replay_checkpoint_index& index) {
  if (index.header.trace_version != context_.header.version) {
    set_error("checkpoint trace version mismatch");
    return false;
  }
  if (index.header.trace_flags != context_.header.flags) {
    set_error("checkpoint trace flags mismatch");
    return false;
  }
  if (index.header.arch != context_.header.arch) {
    set_error("checkpoint architecture mismatch");
    return false;
  }
  if (!context_.register_specs.empty() && index.header.register_count != context_.register_specs.size()) {
    set_error("checkpoint register count mismatch");
    return false;
  }
  return true;
}

const replay_checkpoint_entry* replay_session::find_checkpoint(uint64_t thread_id, uint64_t sequence) const {
  if (!checkpoint_index_) {
    return nullptr;
  }
  return checkpoint_index_->find_checkpoint(thread_id, sequence);
}

std::optional<replay_notice> replay_session::take_notice() {
  if (!notice_.has_value()) {
    return std::nullopt;
  }
  auto out = *notice_;
  notice_.reset();
  return out;
}

void replay_session::reset_instruction_cursor() {
  if (instruction_cursor_.has_value()) {
    instruction_cursor_->reset();
  }
  notice_.reset();
}


bool replay_session::step_flow_internal(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!stateful_flow_cursor_.has_value()) {
    set_error("flow cursor not ready");
    return false;
  }

  flow_step step{};
  if (!stateful_flow_cursor_->step_forward(step)) {
    set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
    return false;
  }

  out = step;
  return true;
}

bool replay_session::step_flow_backward_internal(flow_step& out) {
  clear_error();

  if (!open_) {
    set_error("session not open");
    return false;
  }
  if (!flow_cursor_.has_value() || !stateful_flow_cursor_.has_value()) {
    set_error("flow cursor not ready");
    return false;
  }
  if (!has_position_) {
    set_error("no current position");
    return false;
  }
  if (current_step_.sequence == 0) {
    set_error(replay_error_kind::begin_of_trace, "at start of trace");
    return false;
  }

  bool track_state = config_.track_registers || config_.track_memory;
  uint64_t target = current_step_.sequence - 1;

  if (track_state) {
    if (checkpoint_index_) {
      const auto* checkpoint = find_checkpoint(active_thread_id_, target);
      if (checkpoint) {
        stateful_flow_cursor_->configure(context_, config_.track_registers, config_.track_memory);
        if (!apply_checkpoint(*checkpoint)) {
          return false;
        }
        if (!flow_cursor_->seek_from_location(active_thread_id_, target, checkpoint->location)) {
          set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
          return false;
        }
        flow_step step{};
        if (!stateful_flow_cursor_->step_forward(step)) {
          set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
          return false;
        }
        out = step;
        return true;
      }
    }

    std::optional<trace_anchor> snapshot;
    if (config_.index) {
      snapshot = config_.index->find_snapshot(active_thread_id_, target);
      if (snapshot.has_value() && snapshot->sequence == target) {
        if (target > 0) {
          snapshot = config_.index->find_snapshot(active_thread_id_, target - 1);
        } else {
          snapshot.reset();
        }
      }
    }

    stateful_flow_cursor_->configure(context_, config_.track_registers, config_.track_memory);
    if (snapshot.has_value()) {
      if (!flow_cursor_->seek_from_location(
              active_thread_id_, target, {snapshot->chunk_index, snapshot->record_offset}
          )) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
        return false;
      }
    } else {
      if (!flow_cursor_->seek(active_thread_id_, target)) {
        set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
        return false;
      }
    }

    flow_step step{};
    if (!stateful_flow_cursor_->step_forward(step)) {
      set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
      return false;
    }
    out = step;
    return true;
  }

  flow_step step{};
  if (!stateful_flow_cursor_->step_backward(step)) {
    set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
    return false;
  }

  out = step;
  return true;
}

void replay_session::clear_error() {
  error_.clear();
  error_kind_ = replay_error_kind::none;
}

void replay_session::set_error(const std::string& message) { set_error(replay_error_kind::other, message); }

void replay_session::set_error(replay_error_kind kind, const std::string& message) {
  error_ = message;
  error_kind_ = kind;
}

} // namespace w1::rewind
