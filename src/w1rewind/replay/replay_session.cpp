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
  bool empty_uuid = true;
  for (auto byte : config_.context.header.trace_uuid) {
    if (byte != 0) {
      empty_uuid = false;
      break;
    }
  }
  if (empty_uuid) {
    set_error("replay context required");
    return false;
  }

  context_ = config_.context;
  block_decoder_ = config_.block_decoder;
  state_.set_register_files(context_.register_files);
  bool track_mappings = config_.track_mappings || context_.features.has_mapping_events;
  if (track_mappings) {
    mapping_state_.emplace();
    std::string mapping_error;
    if (!mapping_state_->reset(context_.mappings, mapping_error)) {
      set_error(mapping_error.empty() ? "invalid mapping snapshot" : mapping_error);
      return false;
    }
  } else {
    mapping_state_.reset();
  }

  state_applier_.emplace(context_);
  record_stream_cursor stream_cursor(config_.stream);
  flow_extractor extractor(&context_);
  history_window history(config_.history_size);
  flow_cursor_.emplace(std::move(stream_cursor), std::move(extractor), std::move(history), config_.index);
  if (!flow_cursor_->open()) {
    set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
    return false;
  }

  stateful_flow_cursor_.emplace(*flow_cursor_, *state_applier_, state_);
  if (!stateful_flow_cursor_->configure(
          context_, config_.track_registers, config_.track_memory, track_mappings ? &*mapping_state_ : nullptr
      )) {
    set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
    return false;
  }
  instruction_cursor_.emplace(*stateful_flow_cursor_);
  instruction_cursor_->set_decoder(block_decoder_);
  instruction_cursor_->set_strict(config_.strict_instructions);

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
  mapping_state_.reset();
  current_position_ = replay_position{};
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

  if (!stateful_flow_cursor_->configure(
          context_, config_.track_registers, config_.track_memory,
          mapping_state_.has_value() ? &*mapping_state_ : nullptr
      )) {
    set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
    return false;
  }

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

  if (!used_checkpoint) {
    if (!flow_cursor_->seek(thread_id, sequence)) {
      set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
      return false;
    }
  }

  active_thread_id_ = thread_id;
  reset_instruction_cursor();
  has_position_ = false;
  current_position_ = replay_position{};
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
  current_position_.flow = step;
  if (step.is_block) {
    current_position_.kind = position_kind::block;
    current_position_.instruction.reset();
    current_step_ = step;
  } else {
    current_position_.kind = position_kind::instruction;
    current_position_.instruction = step;
    current_step_ = step;
  }
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
  current_position_.flow = step;
  if (step.is_block) {
    current_position_.kind = position_kind::block;
    current_position_.instruction.reset();
    current_step_ = step;
  } else {
    current_position_.kind = position_kind::instruction;
    current_position_.instruction = step;
    current_step_ = step;
  }
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

  if (stateful_flow_cursor_.has_value()) {
    current_position_.flow = stateful_flow_cursor_->current_step();
  } else {
    current_position_.flow = step;
  }
  if (step.is_block) {
    current_position_.kind = position_kind::block;
    current_position_.instruction.reset();
    current_step_ = step;
  } else {
    current_position_.kind = position_kind::instruction;
    current_position_.instruction = step;
    current_step_ = step;
  }
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

  if (stateful_flow_cursor_.has_value()) {
    current_position_.flow = stateful_flow_cursor_->current_step();
  } else {
    current_position_.flow = step;
  }
  if (step.is_block) {
    current_position_.kind = position_kind::block;
    current_position_.instruction.reset();
    current_step_ = step;
  } else {
    current_position_.kind = position_kind::instruction;
    current_position_.instruction = step;
    current_step_ = step;
  }
  has_position_ = true;
  return true;
}

bool replay_session::sync_instruction_position(bool forward) {
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

  replay_position normalized = current_position_;
  position_normalizer normalizer(block_decoder_);
  std::string error;
  if (!normalizer.normalize(context_, normalized, forward, error)) {
    set_error(error.empty() ? "failed to normalize position" : error);
    return false;
  }

  if (normalized.instruction.has_value()) {
    if (!instruction_cursor_->set_position(
            *normalized.instruction,
            forward ? replay_instruction_cursor::position_bias::start : replay_instruction_cursor::position_bias::end
        )) {
      set_error(
          instruction_cursor_->error().empty() ? "failed to sync instruction position" : instruction_cursor_->error()
      );
      return false;
    }
    if (auto notice = instruction_cursor_->take_notice(); notice.has_value()) {
      notice_ = notice;
    }
    current_step_ = *normalized.instruction;
  } else {
    current_step_ = normalized.flow;
  }

  current_position_ = normalized;
  has_position_ = true;
  return true;
}

std::vector<std::optional<uint64_t>> replay_session::read_registers() const {
  const size_t count = context_.default_registers.size();
  auto out = build_unknown_registers(count);
  if (!config_.track_registers || !stateful_flow_cursor_.has_value()) {
    return out;
  }

  endian byte_order = endian::unknown;
  if (context_.arch.has_value()) {
    byte_order = context_.arch->byte_order;
  }

  for (size_t i = 0; i < count; ++i) {
    const auto& spec = context_.default_registers[i];
    out[i] = state_.register_value(0, spec.reg_id, byte_order);
  }
  return out;
}

bool replay_session::read_register_bytes(uint32_t reg_id, std::span<std::byte> out, bool& known) const {
  known = false;
  if (!config_.track_registers || !stateful_flow_cursor_.has_value()) {
    return true;
  }
  if (reg_id >= context_.default_registers.size()) {
    return false;
  }
  const auto& spec = context_.default_registers[reg_id];
  size_t size = (spec.bit_size + 7u) / 8u;
  if (size == 0 || out.size() < size) {
    return false;
  }
  return state_.copy_register_bytes(0, spec.reg_id, out, known);
}

memory_read replay_session::read_memory(uint64_t address, size_t size) const {
  if (!config_.track_memory || !stateful_flow_cursor_.has_value()) {
    return build_unknown_memory(size);
  }
  return state_.read_memory(0, address, size);
}

const replay_state* replay_session::state() const {
  if (!stateful_flow_cursor_.has_value() || (!config_.track_registers && !config_.track_memory)) {
    return nullptr;
  }
  return &state_;
}

const mapping_state* replay_session::mappings() const {
  if (!mapping_state_.has_value()) {
    return nullptr;
  }
  return &*mapping_state_;
}

bool replay_session::apply_checkpoint(const replay_checkpoint_entry& checkpoint) {
  state_.reset();
  state_.set_register_files(context_.register_files);
  if (config_.track_registers) {
    std::string error;
    if (!state_.apply_register_snapshot(checkpoint.regfile_id, checkpoint.registers, error)) {
      set_error(error.empty() ? "failed to apply checkpoint registers" : error);
      return false;
    }
  }
  if (config_.track_memory) {
    state_.set_memory_segments(checkpoint.memory_segments);
  }
  if (mapping_state_.has_value()) {
    if (checkpoint_index_ && (checkpoint_index_->header.flags & k_checkpoint_flag_has_mappings) != 0) {
      std::string mapping_error;
      if (!mapping_state_->reset(checkpoint.mappings, mapping_error)) {
        set_error(mapping_error.empty() ? "invalid checkpoint mappings" : mapping_error);
        return false;
      }
    } else {
      std::string mapping_error;
      if (!mapping_state_->reset(context_.mappings, mapping_error)) {
        set_error(mapping_error.empty() ? "invalid mapping snapshot" : mapping_error);
        return false;
      }
    }
  }
  return true;
}

bool replay_session::validate_checkpoint(const replay_checkpoint_index& index) {
  if (index.header.trace_uuid != context_.header.trace_uuid) {
    set_error("checkpoint trace uuid mismatch");
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
        if (!stateful_flow_cursor_->configure(
                context_, config_.track_registers, config_.track_memory,
                mapping_state_.has_value() ? &*mapping_state_ : nullptr
            )) {
          set_error(
              map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error())
          );
          return false;
        }
        if (!apply_checkpoint(*checkpoint)) {
          return false;
        }
        if (!flow_cursor_->seek_from_location(active_thread_id_, target, checkpoint->location)) {
          set_error(map_flow_error_kind(flow_cursor_->error_kind()), std::string(flow_cursor_->error()));
          return false;
        }
        flow_step step{};
        if (!stateful_flow_cursor_->step_forward(step)) {
          set_error(
              map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error())
          );
          return false;
        }
        out = step;
        return true;
      }
    }

    std::optional<trace_anchor> anchor;
    if (config_.index) {
      anchor = config_.index->find_anchor(active_thread_id_, target);
      if (anchor.has_value() && anchor->sequence > target) {
        anchor.reset();
      }
      if (anchor.has_value() && anchor->sequence == target) {
        if (target > 0) {
          anchor = config_.index->find_anchor(active_thread_id_, target - 1);
          if (anchor.has_value() && anchor->sequence > target - 1) {
            anchor.reset();
          }
        } else {
          anchor.reset();
        }
      }
    }

    if (!stateful_flow_cursor_->configure(
            context_, config_.track_registers, config_.track_memory,
            mapping_state_.has_value() ? &*mapping_state_ : nullptr
        )) {
      set_error(map_flow_error_kind(stateful_flow_cursor_->error_kind()), std::string(stateful_flow_cursor_->error()));
      return false;
    }
    if (anchor.has_value()) {
      if (!flow_cursor_->seek_from_location(active_thread_id_, target, {anchor->chunk_index, anchor->record_offset})) {
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
