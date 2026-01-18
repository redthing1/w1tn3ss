#include "doctest/doctest.hpp"

#include "w1replay/gdb/run_policy.hpp"

using w1replay::gdb::run_policy;
using w1replay::gdb::step_mode;

TEST_CASE("run_policy chooses flow when instruction stepping is unavailable") {
  run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = false;

  CHECK(!policy.can_instruction_step());
  CHECK(policy.choose_step_mode(gdbstub::resume_action::step, false) == step_mode::flow);
  CHECK(policy.choose_step_mode(gdbstub::resume_action::cont, false) == step_mode::flow);
}

TEST_CASE("run_policy prefers instruction stepping for step actions") {
  run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  CHECK(policy.can_instruction_step());
  CHECK(policy.choose_step_mode(gdbstub::resume_action::step, false) == step_mode::instruction);
}

TEST_CASE("run_policy chooses instruction stepping for continue when needed") {
  run_policy policy{};
  policy.trace_is_block = true;
  policy.decoder_available = true;

  CHECK(policy.choose_step_mode(gdbstub::resume_action::cont, false) == step_mode::flow);

  policy.prefer_instruction_steps = true;
  CHECK(policy.choose_step_mode(gdbstub::resume_action::cont, false) == step_mode::instruction);

  policy.prefer_instruction_steps = false;
  CHECK(policy.choose_step_mode(gdbstub::resume_action::cont, true) == step_mode::instruction);
}
