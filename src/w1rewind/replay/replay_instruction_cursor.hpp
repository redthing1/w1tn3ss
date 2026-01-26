#pragma once

#include <optional>
#include <string>

#include "block_decoder.hpp"
#include "stateful_flow_cursor.hpp"

namespace w1::rewind {

enum class replay_notice_kind { none, decode_unavailable, decode_failed };

struct replay_notice {
  replay_notice_kind kind = replay_notice_kind::none;
  std::string message;
};

class replay_instruction_cursor {
public:
  explicit replay_instruction_cursor(stateful_flow_cursor& flow);

  void set_decoder(block_decoder* decoder) { decoder_ = decoder; }
  void set_strict(bool strict) { strict_ = strict; }
  bool strict() const { return strict_; }
  void reset();
  void sync_with_flow_step(const flow_step& step);
  enum class position_bias { start, end };
  bool set_position(const flow_step& step, position_bias bias = position_bias::start);

  bool step_forward(flow_step& out);
  bool step_backward(flow_step& out);

  std::optional<replay_notice> take_notice();
  const std::string& error() const { return error_; }
  bool has_position() const { return has_position_; }
  const flow_step& current_step() const { return current_step_; }

private:
  struct instruction_state {
    flow_step base_step{};
    decoded_block block{};
    size_t instruction_index = 0;
    bool active = false;
  };

  bool is_block_trace() const;
  bool set_instruction_state(const flow_step& flow, size_t instruction_index, bool set_notice_on_failure);
  bool build_instruction_step(const instruction_state& state, flow_step& out) const;
  bool fallback_to_flow_forward(flow_step& out, replay_notice notice);
  bool fallback_to_flow_backward(flow_step& out, replay_notice notice);

  stateful_flow_cursor& flow_;
  block_decoder* decoder_ = nullptr;
  bool strict_ = false;
  instruction_state instruction_state_{};
  flow_step current_step_{};
  bool has_position_ = false;
  std::optional<replay_notice> notice_;
  std::string error_;
};

} // namespace w1::rewind
