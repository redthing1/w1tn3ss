#include "replay_position.hpp"

namespace w1::rewind {

bool position_normalizer::normalize(
    const replay_context& context, replay_position& pos, bool forward_bias, std::string& error
) const {
  error.clear();

  if (pos.kind == position_kind::instruction && pos.instruction.has_value()) {
    return true;
  }

  if (!pos.flow.is_block) {
    pos.kind = position_kind::instruction;
    pos.instruction = pos.flow;
    return true;
  }

  if (!decoder_) {
    error = "block decoder unavailable";
    return false;
  }

  decoded_block decoded{};
  if (!decoder_->decode_block(context, pos.flow, decoded, error)) {
    if (error.empty()) {
      error = "block decode failed";
    }
    return false;
  }

  if (decoded.instructions.empty()) {
    error = "decoded block has no instructions";
    return false;
  }

  size_t index = forward_bias ? 0 : decoded.instructions.size() - 1;
  const auto& inst = decoded.instructions[index];

  flow_step instruction = pos.flow;
  instruction.is_block = false;
  instruction.address = inst.address;
  instruction.size = inst.size;

  pos.kind = position_kind::instruction;
  pos.instruction = instruction;
  return true;
}

} // namespace w1::rewind
