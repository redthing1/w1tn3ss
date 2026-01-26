#include <array>
#include <cstddef>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/replay/replay_state_applier.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

TEST_CASE("w1rewind replay state applier applies snapshot state and stack segments") {
  using namespace w1::rewind::test_helpers;
  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::replay_context context{};
  context.register_files = {make_register_file(0, {"r0", "sp"}, arch)};

  w1::rewind::replay_state state;
  state.set_register_files(context.register_files);

  w1::rewind::snapshot_record snapshot{};
  snapshot.thread_id = 1;
  snapshot.regfile_id = 0;
  snapshot.registers = {
      make_reg_write_entry(0, 0x1111),
      make_reg_write_entry(1, 0x2000),
  };
  w1::rewind::memory_segment segment{};
  segment.space_id = 0;
  segment.base = 0x2000;
  segment.bytes = {0xAA, 0xBB};
  snapshot.memory_segments.push_back(std::move(segment));

  w1::rewind::replay_state_applier applier(context);
  std::string error;
  REQUIRE(applier.apply_snapshot(snapshot, 1, true, true, state, error));

  CHECK(state.register_value(0, 0, w1::rewind::endian::little) == 0x1111);
  CHECK(state.register_value(0, 1, w1::rewind::endian::little) == 0x2000);

  auto mem = state.read_memory(0, 0x2000, 2);
  REQUIRE(mem.bytes.size() == 2);
  REQUIRE(mem.known.size() == 2);
  CHECK(mem.known[0] == 1);
  CHECK(mem.known[1] == 1);
  CHECK(std::to_integer<uint8_t>(mem.bytes[0]) == 0xAA);
  CHECK(std::to_integer<uint8_t>(mem.bytes[1]) == 0xBB);
}

TEST_CASE("w1rewind replay state applier applies read accesses with known values") {
  using namespace w1::rewind::test_helpers;
  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::replay_context context{};
  context.register_files = {make_register_file(0, {"r0", "sp"}, arch)};

  w1::rewind::replay_state state;
  state.set_register_files(context.register_files);

  w1::rewind::reg_write_record deltas{};
  deltas.thread_id = 2;
  deltas.sequence = 0;
  deltas.regfile_id = 0;
  deltas.entries = {make_reg_write_entry(0, 0x2222)};

  w1::rewind::mem_access_record mem{};
  mem.thread_id = 1;
  mem.sequence = 0;
  mem.space_id = 0;
  mem.op = w1::rewind::mem_access_op::read;
  mem.flags = w1::rewind::mem_access_value_known;
  mem.address = 0x3000;
  mem.access_size = 1;
  mem.value = {0xCC};

  w1::rewind::replay_state_applier applier(context);
  std::string error;
  REQUIRE(applier.apply_record(deltas, 1, true, true, state, error));
  REQUIRE(applier.apply_record(mem, 1, true, true, state, error));

  CHECK(!state.register_value(0, 0, w1::rewind::endian::little).has_value());
  auto mem_bytes = state.read_memory(0, 0x3000, 1);
  REQUIRE(mem_bytes.bytes.size() == 1);
  REQUIRE(mem_bytes.known.size() == 1);
  CHECK(mem_bytes.known[0] == 1);
  CHECK(std::to_integer<uint8_t>(mem_bytes.bytes[0]) == 0xCC);
}

TEST_CASE("w1rewind replay state applier applies register byte values") {
  using namespace w1::rewind::test_helpers;
  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::replay_context context{};
  context.register_files = {make_register_file(0, {"r0", "v0"}, arch)};

  w1::rewind::replay_state state;
  state.set_register_files(context.register_files);

  w1::rewind::reg_write_record bytes{};
  bytes.thread_id = 1;
  bytes.sequence = 0;
  bytes.regfile_id = 0;
  bytes.entries = {w1::rewind::reg_write_entry{
      w1::rewind::reg_ref_kind::reg_id,
      0,
      0,
      16,
      1,
      "",
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
  }};

  w1::rewind::replay_state_applier applier(context);
  std::string error;
  REQUIRE(applier.apply_record(bytes, 1, true, false, state, error));

  std::array<std::byte, 16> buffer{};
  bool known = false;
  REQUIRE(state.copy_register_bytes(0, 1, buffer, known));
  CHECK(known);
  CHECK(std::to_integer<uint8_t>(buffer[0]) == 0x00);
  CHECK(std::to_integer<uint8_t>(buffer[15]) == 0x0f);
}

TEST_CASE("w1rewind replay state applier applies name-based register writes") {
  using namespace w1::rewind::test_helpers;
  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::replay_context context{};
  context.register_files = {make_register_file(0, {"pc", "sp"}, arch)};

  w1::rewind::replay_state state;
  state.set_register_files(context.register_files);

  w1::rewind::reg_write_record writes{};
  writes.thread_id = 1;
  writes.sequence = 0;
  writes.regfile_id = 0;

  w1::rewind::reg_write_entry entry{};
  entry.ref_kind = w1::rewind::reg_ref_kind::reg_name;
  entry.byte_offset = 0;
  entry.byte_size = 8;
  entry.reg_name = "pc";
  entry.value = encode_value(0xAABBCCDDEEFF0011ULL, entry.byte_size, w1::rewind::endian::little);
  writes.entries = {entry};

  w1::rewind::replay_state_applier applier(context);
  std::string error;
  REQUIRE(applier.apply_record(writes, 1, true, true, state, error));

  auto reg_id = w1::rewind::find_register_id_by_name(context.register_files[0].registers, "pc");
  REQUIRE(reg_id.has_value());
  CHECK(state.register_value(0, *reg_id, w1::rewind::endian::little) == 0xAABBCCDDEEFF0011ULL);
}

TEST_CASE("w1rewind replay state applier rejects unknown register names") {
  using namespace w1::rewind::test_helpers;
  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::replay_context context{};
  context.register_files = {make_register_file(0, {"pc"}, arch)};

  w1::rewind::replay_state state;
  state.set_register_files(context.register_files);

  w1::rewind::reg_write_record writes{};
  writes.thread_id = 1;
  writes.sequence = 0;
  writes.regfile_id = 0;

  w1::rewind::reg_write_entry entry{};
  entry.ref_kind = w1::rewind::reg_ref_kind::reg_name;
  entry.byte_offset = 0;
  entry.byte_size = 8;
  entry.reg_name = "unknown";
  entry.value = encode_value(0x1122334455667788ULL, entry.byte_size, w1::rewind::endian::little);
  writes.entries = {entry};

  w1::rewind::replay_state_applier applier(context);
  std::string error;
  CHECK_FALSE(applier.apply_record(writes, 1, true, true, state, error));
  CHECK(error.find("unknown register name") != std::string::npos);
}
