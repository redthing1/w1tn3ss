#include "stateful_flow_cursor.hpp"

namespace w1::rewind {

stateful_flow_cursor::stateful_flow_cursor(flow_cursor& flow, replay_state_applier& applier, replay_state& state)
    : flow_(flow), applier_(applier), state_(state) {
  flow_.set_observer(this);
}

stateful_flow_cursor::~stateful_flow_cursor() { flow_.set_observer(nullptr); }

void stateful_flow_cursor::configure(const replay_context& context, bool track_registers, bool track_memory) {
  track_registers_ = track_registers;
  track_memory_ = track_memory;
  flow_.set_history_enabled(!(track_registers_ || track_memory_));
  reset_state(context);
}

bool stateful_flow_cursor::step_forward(flow_step& out) { return flow_.step_forward(out); }

bool stateful_flow_cursor::step_backward(flow_step& out) {
  if (track_registers_ || track_memory_) {
    reset_state(flow_.context());
  }
  return flow_.step_backward(out);
}

bool stateful_flow_cursor::on_record(const trace_record& record, uint64_t active_thread_id, std::string& error) {
  if (!track_registers_ && !track_memory_) {
    return true;
  }
  if (!applier_.apply_record(record, active_thread_id, track_registers_, track_memory_, state_)) {
    error = "failed to apply trace record";
    return false;
  }
  return true;
}

void stateful_flow_cursor::reset_state(const replay_context& context) {
  state_.reset();
  if (track_registers_) {
    state_.set_register_specs(context.register_specs);
  }
}

} // namespace w1::rewind
