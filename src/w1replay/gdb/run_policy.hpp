#pragma once

#include "gdbstub/target.hpp"

namespace w1replay::gdb {

enum class step_mode { flow, instruction };

struct run_policy {
  bool trace_is_block = false;
  bool decoder_available = false;
  bool prefer_instruction_steps = false;

  bool can_instruction_step() const { return trace_is_block && decoder_available; }

  step_mode choose_step_mode(gdbstub::resume_action action, bool has_breakpoints) const {
    if (!can_instruction_step()) {
      return step_mode::flow;
    }
    if (action == gdbstub::resume_action::cont) {
      return (prefer_instruction_steps || has_breakpoints) ? step_mode::instruction : step_mode::flow;
    }
    return step_mode::instruction;
  }
};

} // namespace w1replay::gdb
