#include "replay_instruction_cursor.hpp"

#include <limits>

namespace w1::rewind {

namespace {

replay_notice make_notice(replay_notice_kind kind, const std::string& message) {
  replay_notice notice{};
  notice.kind = kind;
  notice.message = message;
  return notice;
}

} // namespace

replay_instruction_cursor::replay_instruction_cursor(replay_flow_cursor& flow) : flow_(flow) {}

void replay_instruction_cursor::reset() {
  instruction_state_ = instruction_state{};
  current_step_ = flow_step{};
  has_position_ = false;
  notice_.reset();
  error_.clear();
}

void replay_instruction_cursor::sync_with_flow_step(const flow_step& step) {
  instruction_state_ = instruction_state{};
  current_step_ = step;
  has_position_ = true;
  notice_.reset();
  error_.clear();
}

bool replay_instruction_cursor::step_forward(flow_step& out) {
  error_.clear();

  if (!is_block_trace()) {
    return fallback_to_flow_forward(out, replay_notice{});
  }
  if (decoder_ == nullptr) {
    return fallback_to_flow_forward(
        out, make_notice(replay_notice_kind::decode_unavailable, "block decoder unavailable; using flow steps")
    );
  }

  if (instruction_state_.active) {
    auto next_index = instruction_state_.instruction_index + 1;
    if (next_index < instruction_state_.block.instructions.size()) {
      instruction_state_.instruction_index = next_index;
      flow_step step{};
      if (!build_instruction_step(instruction_state_, step)) {
        return false;
      }
      current_step_ = step;
      has_position_ = true;
      out = step;
      return true;
    }
    instruction_state_ = instruction_state{};
  }

  flow_step flow{};
  if (!flow_.step_forward(flow)) {
    error_ = flow_.error();
    return false;
  }

  if (!flow.is_block) {
    current_step_ = flow;
    has_position_ = true;
    out = flow;
    return true;
  }

  if (!set_instruction_state(flow, 0, true)) {
    current_step_ = flow;
    has_position_ = true;
    out = flow;
    return true;
  }

  flow_step step{};
  if (!build_instruction_step(instruction_state_, step)) {
    current_step_ = flow;
    has_position_ = true;
    out = flow;
    return true;
  }

  current_step_ = step;
  has_position_ = true;
  out = step;
  return true;
}

bool replay_instruction_cursor::step_backward(flow_step& out) {
  error_.clear();

  if (!flow_.has_position()) {
    error_ = "no current position";
    return false;
  }

  if (!is_block_trace()) {
    return fallback_to_flow_backward(out, replay_notice{});
  }
  if (decoder_ == nullptr) {
    return fallback_to_flow_backward(
        out, make_notice(replay_notice_kind::decode_unavailable, "block decoder unavailable; using flow steps")
    );
  }

  if (instruction_state_.active) {
    if (instruction_state_.instruction_index > 0) {
      instruction_state_.instruction_index -= 1;
      flow_step step{};
      if (!build_instruction_step(instruction_state_, step)) {
        return false;
      }
      current_step_ = step;
      has_position_ = true;
      out = step;
      return true;
    }
    instruction_state_ = instruction_state{};
  }

  if (has_position_ && current_step_.is_block) {
    if (set_instruction_state(current_step_, 0, true)) {
      instruction_state_.instruction_index = instruction_state_.block.instructions.size() - 1;
      flow_step step{};
      if (!build_instruction_step(instruction_state_, step)) {
        return false;
      }
      current_step_ = step;
      has_position_ = true;
      out = step;
      return true;
    }
  }

  flow_step flow{};
  if (!flow_.step_backward(flow)) {
    error_ = flow_.error();
    return false;
  }

  if (!flow.is_block) {
    current_step_ = flow;
    has_position_ = true;
    out = flow;
    return true;
  }

  if (!set_instruction_state(flow, 0, true)) {
    current_step_ = flow;
    has_position_ = true;
    out = flow;
    return true;
  }

  instruction_state_.instruction_index = instruction_state_.block.instructions.size() - 1;
  flow_step step{};
  if (!build_instruction_step(instruction_state_, step)) {
    current_step_ = flow;
    has_position_ = true;
    out = flow;
    return true;
  }

  current_step_ = step;
  has_position_ = true;
  out = step;
  return true;
}

std::optional<replay_notice> replay_instruction_cursor::take_notice() {
  if (!notice_.has_value()) {
    return std::nullopt;
  }
  auto out = *notice_;
  notice_.reset();
  return out;
}

bool replay_instruction_cursor::is_block_trace() const { return flow_.context().has_blocks(); }

bool replay_instruction_cursor::set_instruction_state(
    const flow_step& flow, size_t instruction_index, bool set_notice_on_failure
) {
  if (!flow.is_block) {
    return false;
  }
  replay_decoded_block decoded{};
  std::string decode_error;
  if (!decoder_ || !decoder_->decode_block(flow_.context(), flow, decoded, decode_error) ||
      decoded.instructions.empty()) {
    if (set_notice_on_failure) {
      std::string message = decode_error.empty() ? "block decode failed; using flow steps" : decode_error;
      notice_ = make_notice(replay_notice_kind::decode_failed, message);
    }
    return false;
  }

  if (instruction_index >= decoded.instructions.size()) {
    if (set_notice_on_failure) {
      notice_ = make_notice(replay_notice_kind::decode_failed, "decoded instruction index out of range");
    }
    return false;
  }

  instruction_state_.active = true;
  instruction_state_.base_step = flow;
  instruction_state_.block = std::move(decoded);
  instruction_state_.instruction_index = instruction_index;
  return true;
}

bool replay_instruction_cursor::build_instruction_step(const instruction_state& state, flow_step& out) const {
  if (!state.active || state.block.instructions.empty()) {
    return false;
  }
  const auto& inst = state.block.instructions[state.instruction_index];
  flow_step step = state.base_step;
  step.is_block = false;
  step.size = inst.size;
  if (inst.offset > std::numeric_limits<uint64_t>::max() - state.block.address) {
    return false;
  }
  step.address = state.block.address + inst.offset;
  out = step;
  return true;
}

bool replay_instruction_cursor::fallback_to_flow_forward(flow_step& out, replay_notice notice) {
  if (notice.kind != replay_notice_kind::none) {
    notice_ = notice;
  }
  flow_step flow{};
  if (!flow_.step_forward(flow)) {
    error_ = flow_.error();
    return false;
  }
  current_step_ = flow;
  has_position_ = true;
  out = flow;
  return true;
}

bool replay_instruction_cursor::fallback_to_flow_backward(flow_step& out, replay_notice notice) {
  if (notice.kind != replay_notice_kind::none) {
    notice_ = notice;
  }
  flow_step flow{};
  if (!flow_.step_backward(flow)) {
    error_ = flow_.error();
    return false;
  }
  current_step_ = flow;
  has_position_ = true;
  out = flow;
  return true;
}

} // namespace w1::rewind
