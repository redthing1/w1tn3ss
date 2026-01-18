#include <array>
#include <cstddef>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_state_applier.hpp"
#include "w1rewind/format/trace_format.hpp"

TEST_CASE("w1rewind replay state applier applies snapshot state and stack snapshot") {
  w1::rewind::replay_context context{};
  context.register_specs = {
      w1::rewind::register_spec{0, "r0", 64, 0, "", w1::rewind::register_class::gpr,
                                w1::rewind::register_value_kind::u64},
      w1::rewind::register_spec{1, "sp", 64, w1::rewind::register_flag_sp, "", w1::rewind::register_class::gpr,
                                w1::rewind::register_value_kind::u64},
  };
  context.register_names = {"r0", "sp"};
  context.sp_reg_id = 1;

  w1::rewind::replay_state state;
  state.set_register_specs(context.register_specs);

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
  context.register_specs = {
      w1::rewind::register_spec{0, "r0", 64, 0, "", w1::rewind::register_class::gpr,
                                w1::rewind::register_value_kind::u64},
      w1::rewind::register_spec{1, "sp", 64, w1::rewind::register_flag_sp, "", w1::rewind::register_class::gpr,
                                w1::rewind::register_value_kind::u64},
  };
  context.register_names = {"r0", "sp"};
  context.sp_reg_id = 1;

  w1::rewind::replay_state state;
  state.set_register_specs(context.register_specs);

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

TEST_CASE("w1rewind replay state applier applies register byte values") {
  w1::rewind::replay_context context{};
  context.register_specs = {
      w1::rewind::register_spec{0, "r0", 64, 0, "", w1::rewind::register_class::gpr,
                                w1::rewind::register_value_kind::u64},
      w1::rewind::register_spec{1, "v0", 128, 0, "", w1::rewind::register_class::simd,
                                w1::rewind::register_value_kind::bytes},
  };
  context.register_names = {"r0", "v0"};

  w1::rewind::replay_state state;
  state.set_register_specs(context.register_specs);

  w1::rewind::register_bytes_record bytes{};
  bytes.thread_id = 1;
  bytes.sequence = 0;
  bytes.entries = {w1::rewind::register_bytes_entry{1, 0, 16}};
  bytes.data = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };

  w1::rewind::replay_state_applier applier(context);
  REQUIRE(applier.apply_record(bytes, 1, true, false, state));

  std::array<std::byte, 16> buffer{};
  bool known = false;
  REQUIRE(state.copy_register_bytes(1, buffer, known));
  CHECK(known);
  CHECK(std::to_integer<uint8_t>(buffer[0]) == 0x00);
  CHECK(std::to_integer<uint8_t>(buffer[15]) == 0x0f);
}
