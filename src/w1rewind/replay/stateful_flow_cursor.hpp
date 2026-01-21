#pragma once

#include <string_view>

#include "flow_cursor.hpp"
#include "replay_state.hpp"
#include "replay_state_applier.hpp"

namespace w1::rewind {

class stateful_flow_cursor final : private flow_record_observer {
public:
  explicit stateful_flow_cursor(flow_cursor& flow, replay_state_applier& applier, replay_state& state);
  ~stateful_flow_cursor() override;

  void configure(const replay_context& context, bool track_registers, bool track_memory);

  bool step_forward(flow_step& out);
  bool step_backward(flow_step& out);

  const replay_state& state() const { return state_; }
  const replay_context& context() const { return flow_.context(); }
  bool has_position() const { return flow_.has_position(); }
  const flow_step& current_step() const { return flow_.current_step(); }
  std::string_view error() const { return flow_.error(); }
  flow_error_kind error_kind() const { return flow_.error_kind(); }

private:
  bool on_record(const trace_record& record, uint64_t active_thread_id, std::string& error) override;
  void reset_state(const replay_context& context);

  flow_cursor& flow_;
  replay_state_applier& applier_;
  replay_state& state_;
  bool track_registers_ = false;
  bool track_memory_ = false;
};

} // namespace w1::rewind
