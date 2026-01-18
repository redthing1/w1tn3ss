#include "doctest/doctest.hpp"

#include "w1tn3ss/runtime/rewind/replay_state_applier.hpp"
#include "w1tn3ss/runtime/rewind/trace_format.hpp"

TEST_CASE("w1rewind replay state applier applies snapshot state and stack snapshot") {
  w1::rewind::replay_context context{};
  context.register_names = {"r0", "sp"};
  context.sp_reg_id = 1;

  w1::rewind::replay_state state;
  state.set_register_count(context.register_names.size());

  w1::rewind::snapshot_record snapshot{};
  snapshot.thread_id = 1;
  snapshot.registers = {
      w1::rewind::register_delta{0, 0x1111},
      w1::rewind::register_delta{1, 0x2000},
  };
  snapshot.stack_snapshot = {0xAA, 0xBB};

  w1::rewind::replay_state_applier applier(context);
  REQUIRE(applier.apply_snapshot(snapshot, 1, true, true, state));

  CHECK(state.register_value(0) == 0x1111);
  CHECK(state.register_value(1) == 0x2000);

  auto layout = w1::rewind::compute_stack_snapshot_layout(0x2000, snapshot.stack_snapshot.size());
  auto mem = state.read_memory(layout.base, snapshot.stack_snapshot.size());
  REQUIRE(mem.size() == snapshot.stack_snapshot.size());
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
