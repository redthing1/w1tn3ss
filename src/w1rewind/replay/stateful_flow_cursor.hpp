#pragma once

#include <string_view>

#include "flow_cursor.hpp"
#include "mapping_state.hpp"
#include "replay_state.hpp"
#include "replay_state_applier.hpp"

namespace w1::rewind {

class stateful_flow_cursor final : private flow_record_observer {
public:
  explicit stateful_flow_cursor(flow_cursor& flow, replay_state_applier& applier, replay_state& state);
  ~stateful_flow_cursor() override;

  bool configure(const replay_context& context, bool track_registers, bool track_memory, mapping_state* mappings);

  bool step_forward(flow_step& out);
  bool step_backward(flow_step& out);

  const replay_state& state() const { return state_; }
  const replay_context& context() const { return flow_.context(); }
  bool has_position() const { return flow_.has_position(); }
  const flow_step& current_step() const { return flow_.current_step(); }
  std::string_view error() const { return error_.empty() ? flow_.error() : std::string_view(error_); }
  flow_error_kind error_kind() const { return error_kind_ == flow_error_kind::none ? flow_.error_kind() : error_kind_; }

private:
  bool on_record(const trace_record& record, uint64_t active_thread_id, std::string& error) override;
  bool reset_state(const replay_context& context, std::string& error);
  void clear_error();
  void set_error(flow_error_kind kind, std::string message);

  flow_cursor& flow_;
  replay_state_applier& applier_;
  replay_state& state_;
  bool track_registers_ = false;
  bool track_memory_ = false;
  bool track_mappings_ = false;
  mapping_state* mapping_state_ = nullptr;
  std::string error_;
  flow_error_kind error_kind_ = flow_error_kind::none;
};

} // namespace w1::rewind
