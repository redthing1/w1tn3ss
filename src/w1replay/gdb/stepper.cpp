#include "stepper.hpp"

namespace w1replay::gdb {

namespace {

constexpr int k_sigtrap = 5;

gdbstub::stop_reason make_stop_reason(
    gdbstub::stop_kind kind,
    int signal,
    uint64_t addr,
    uint64_t thread_id
) {
  gdbstub::stop_reason stop{};
  stop.kind = kind;
  stop.signal = signal;
  stop.addr = addr;
  stop.thread_id = thread_id;
  return stop;
}

stepper_result make_signal_result(uint64_t thread_id) {
  stepper_result out{};
  out.resume.state = gdbstub::resume_result::state::stopped;
  out.resume.stop = make_stop_reason(gdbstub::stop_kind::signal, k_sigtrap, 0, thread_id);
  out.last_stop = out.resume.stop;
  return out;
}

stepper_result make_replay_log_result(gdbstub::replay_log_boundary boundary, uint64_t thread_id) {
  stepper_result out = make_signal_result(thread_id);
  out.resume.stop.replay_log = boundary;
  out.last_stop = out.resume.stop;
  return out;
}

stepper_result make_break_result(uint64_t address, uint64_t thread_id) {
  stepper_result out{};
  out.resume.state = gdbstub::resume_result::state::stopped;
  out.resume.stop = make_stop_reason(gdbstub::stop_kind::sw_break, k_sigtrap, address, thread_id);
  out.last_stop = out.resume.stop;
  return out;
}

bool step_once(w1::rewind::replay_session& session, bool instruction, gdbstub::resume_direction direction) {
  if (direction == gdbstub::resume_direction::reverse) {
    if (instruction) {
      return session.step_instruction_backward();
    }
    return session.step_backward();
  }
  if (instruction) {
    return session.step_instruction();
  }
  return session.step_flow();
}

} // namespace

stepper_result resume_step(
    w1::rewind::replay_session& session,
    const run_policy& policy,
    const std::unordered_set<uint64_t>& breakpoints,
    uint64_t thread_id,
    gdbstub::resume_direction direction
) {
  bool instruction = policy.choose_step_mode(gdbstub::resume_action::step, !breakpoints.empty()) ==
      step_mode::instruction;
  if (!step_once(session, instruction, direction)) {
    auto kind = session.error_kind();
    if (kind == w1::rewind::replay_session::replay_error_kind::begin_of_trace) {
      return make_replay_log_result(gdbstub::replay_log_boundary::begin, thread_id);
    }
    if (kind == w1::rewind::replay_session::replay_error_kind::end_of_trace) {
      return make_replay_log_result(gdbstub::replay_log_boundary::end, thread_id);
    }
    return make_signal_result(thread_id);
  }

  uint64_t address = session.current_step().address;
  if (breakpoints.find(address) != breakpoints.end()) {
    return make_break_result(address, thread_id);
  }
  return make_signal_result(thread_id);
}

stepper_result resume_continue(
    w1::rewind::replay_session& session,
    const run_policy& policy,
    const std::unordered_set<uint64_t>& breakpoints,
    uint64_t thread_id,
    gdbstub::resume_direction direction
) {
  bool instruction = policy.choose_step_mode(gdbstub::resume_action::cont, !breakpoints.empty()) ==
      step_mode::instruction;

  for (;;) {
    if (!step_once(session, instruction, direction)) {
      auto kind = session.error_kind();
      if (kind == w1::rewind::replay_session::replay_error_kind::begin_of_trace) {
        return make_replay_log_result(gdbstub::replay_log_boundary::begin, thread_id);
      }
      if (kind == w1::rewind::replay_session::replay_error_kind::end_of_trace) {
        return make_replay_log_result(gdbstub::replay_log_boundary::end, thread_id);
      }
      return make_signal_result(thread_id);
    }

    uint64_t address = session.current_step().address;
    if (breakpoints.find(address) != breakpoints.end()) {
      return make_break_result(address, thread_id);
    }
  }
}

} // namespace w1replay::gdb
