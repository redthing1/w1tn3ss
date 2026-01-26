#include "stateful_flow_cursor.hpp"

#include <string>

namespace w1::rewind {

stateful_flow_cursor::stateful_flow_cursor(flow_cursor& flow, replay_state_applier& applier, replay_state& state)
    : flow_(flow), applier_(applier), state_(state) {
  flow_.set_observer(this);
}

stateful_flow_cursor::~stateful_flow_cursor() { flow_.set_observer(nullptr); }

bool stateful_flow_cursor::configure(
    const replay_context& context, bool track_registers, bool track_memory, mapping_state* mappings
) {
  clear_error();
  track_registers_ = track_registers;
  track_memory_ = track_memory;
  mapping_state_ = mappings;
  track_mappings_ = mapping_state_ != nullptr;
  flow_.set_history_enabled(!(track_registers_ || track_memory_ || track_mappings_));
  std::string error;
  if (!reset_state(context, error)) {
    set_error(flow_error_kind::other, error.empty() ? "failed to reset replay state" : error);
    return false;
  }
  return true;
}

bool stateful_flow_cursor::step_forward(flow_step& out) {
  clear_error();
  return flow_.step_forward(out);
}

bool stateful_flow_cursor::step_backward(flow_step& out) {
  clear_error();
  if (track_registers_ || track_memory_ || track_mappings_) {
    std::string error;
    if (!reset_state(flow_.context(), error)) {
      set_error(flow_error_kind::other, error.empty() ? "failed to reset replay state" : error);
      return false;
    }
  }
  return flow_.step_backward(out);
}

bool stateful_flow_cursor::on_record(const trace_record& record, uint64_t active_thread_id, std::string& error) {
  std::string apply_error;
  if (track_registers_ || track_memory_) {
    if (!applier_.apply_record(record, active_thread_id, track_registers_, track_memory_, state_, apply_error)) {
      error = apply_error.empty() ? "failed to apply trace record" : apply_error;
      return false;
    }
  }
  if (track_mappings_ && mapping_state_ && std::holds_alternative<mapping_record>(record)) {
    if (!mapping_state_->apply_event(std::get<mapping_record>(record), apply_error)) {
      error = apply_error.empty() ? "failed to apply mapping event" : apply_error;
      return false;
    }
  }
  return true;
}

bool stateful_flow_cursor::reset_state(const replay_context& context, std::string& error) {
  error.clear();
  state_.reset();
  if (track_registers_) {
    state_.set_register_files(context.register_files);
  }
  if (track_mappings_ && mapping_state_) {
    if (!mapping_state_->reset(context.mappings, error)) {
      return false;
    }
  }
  return true;
}

void stateful_flow_cursor::clear_error() {
  error_.clear();
  error_kind_ = flow_error_kind::none;
}

void stateful_flow_cursor::set_error(flow_error_kind kind, std::string message) {
  error_ = std::move(message);
  error_kind_ = kind;
}

} // namespace w1::rewind
