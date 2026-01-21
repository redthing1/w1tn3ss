#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/stepper.hpp"

namespace w1replay::gdb {

run_component::run_component(const adapter_services& services, thread_state& thread)
    : services_(services), thread_(thread) {}

gdbstub::run_capabilities run_component::capabilities() const {
  gdbstub::run_capabilities caps{};
  caps.reverse_step = true;
  caps.reverse_continue = true;
  return caps;
}

gdbstub::resume_result run_component::resume(const gdbstub::resume_request& request) {
  if (!services_.session) {
    gdbstub::resume_result result{};
    result.state = gdbstub::resume_result::state::exited;
    gdbstub::stop_reason stop{};
    stop.kind = gdbstub::stop_kind::exited;
    stop.exit_code = 0;
    if (thread_.active_thread_id != 0) {
      stop.thread_id = thread_.active_thread_id;
    }
    result.stop = stop;
    result.exit_code = 0;
    return result;
  }

  run_policy policy = services_.run_policy;
  static const breakpoint_store empty_breakpoints{};
  const breakpoint_store& breakpoints = services_.breakpoints ? *services_.breakpoints : empty_breakpoints;

  stepper_result result{};
  if (request.action == gdbstub::resume_action::step) {
    result = resume_step(*services_.session, policy, breakpoints, thread_.active_thread_id, request.direction);
  } else if (request.action == gdbstub::resume_action::cont) {
    result = resume_continue(*services_.session, policy, breakpoints, thread_.active_thread_id, request.direction);
  } else {
    result = resume_step(*services_.session, policy, breakpoints, thread_.active_thread_id, request.direction);
  }
  thread_.last_stop = result.last_stop;
  return result.resume;
}

} // namespace w1replay::gdb
