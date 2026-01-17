#include "doctest/doctest.hpp"

#include "w1tn3ss/runtime/rewind/replay_state_applier.hpp"

TEST_CASE("w1rewind replay state applier applies boundary snapshot and stack window") {
  w1::rewind::replay_context context{};
  context.register_names = {"r0", "sp"};
  context.sp_reg_id = 1;

  w1::rewind::replay_state state;
  state.set_register_count(context.register_names.size());

  w1::rewind::boundary_record boundary{};
  boundary.thread_id = 1;
  boundary.registers = {
      w1::rewind::register_delta{0, 0x1111},
      w1::rewind::register_delta{1, 0x2000},
  };
  boundary.stack_window = {0xAA, 0xBB};

  w1::rewind::replay_state_applier applier(context);
  REQUIRE(applier.apply_boundary(boundary, 1, true, true, state));

  CHECK(state.register_value(0) == 0x1111);
  CHECK(state.register_value(1) == 0x2000);

  auto mem = state.read_memory(0x2000, 2);
  REQUIRE(mem.size() == 2);
  CHECK(mem[0].has_value());
  CHECK(mem[1].has_value());
  CHECK(mem[0].value() == 0xAA);
  CHECK(mem[1].value() == 0xBB);
}

TEST_CASE("w1rewind replay state applier ignores non-active thread and read accesses") {
  w1::rewind::replay_context context{};
  context.register_names = {"r0", "sp"};
  context.sp_reg_id = 1;

  w1::rewind::replay_state state;
  state.set_register_count(context.register_names.size());

  w1::rewind::register_delta_record deltas{};
  deltas.thread_id = 2;
  deltas.deltas = {w1::rewind::register_delta{0, 0x2222}};

  w1::rewind::memory_access_record mem{};
  mem.thread_id = 1;
  mem.kind = w1::rewind::memory_access_kind::read;
  mem.address = 0x3000;
  mem.size = 1;
  mem.value_known = true;
  mem.data = {0xCC};

  w1::rewind::replay_state_applier applier(context);
  REQUIRE(applier.apply_record(deltas, 1, true, true, state));
  REQUIRE(applier.apply_record(mem, 1, true, true, state));

  CHECK(!state.register_value(0).has_value());
  auto mem_bytes = state.read_memory(0x3000, 1);
  REQUIRE(mem_bytes.size() == 1);
  CHECK(!mem_bytes[0].has_value());
}
