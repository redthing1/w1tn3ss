#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/stepper.hpp"

namespace w1replay::gdb {

run_component::run_component(adapter_state& state) : state_(state) {}

gdbstub::run_capabilities run_component::capabilities() const {
  gdbstub::run_capabilities caps{};
  caps.reverse_step = true;
  caps.reverse_continue = true;
  return caps;
}

gdbstub::resume_result run_component::resume(const gdbstub::resume_request& request) {
  if (!state_.session) {
    gdbstub::resume_result result{};
    result.state = gdbstub::resume_result::state::exited;
    gdbstub::stop_reason stop{};
    stop.kind = gdbstub::stop_kind::exited;
    stop.exit_code = 0;
    if (state_.active_thread_id != 0) {
      stop.thread_id = state_.active_thread_id;
    }
    result.stop = stop;
    result.exit_code = 0;
    return result;
  }

  run_policy policy = state_.make_run_policy();

  stepper_result result{};
  if (request.action == gdbstub::resume_action::step) {
    result = resume_step(*state_.session, policy, state_.breakpoints, state_.active_thread_id, request.direction);
  } else if (request.action == gdbstub::resume_action::cont) {
    result = resume_continue(*state_.session, policy, state_.breakpoints, state_.active_thread_id, request.direction);
  } else {
    result = resume_step(*state_.session, policy, state_.breakpoints, state_.active_thread_id, request.direction);
  }
  state_.last_stop = result.last_stop;
  return result.resume;
}

} // namespace w1replay::gdb
