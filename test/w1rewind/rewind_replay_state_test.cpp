#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/flow_cursor.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_state.hpp"
#include "w1rewind/replay/replay_state_applier.hpp"
#include "w1rewind/replay/stateful_flow_cursor.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace {

std::vector<std::string> make_register_names(const w1::arch::arch_spec& arch) {
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return {"rax", "rsp"};
  case w1::arch::mode::x86_32:
    return {"eax", "esp"};
  case w1::arch::mode::aarch64:
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return {"x0", "sp"};
  default:
    break;
  }
  return {"r0", "sp"};
}

} // namespace

TEST_CASE("w1rewind replay cursor applies register and memory state") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_state.trace");
  fs::path index_path = temp_path("w1rewind_replay_state.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);

  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.replay_state"));
  write_basic_metadata(handle.builder, "x86_64", arch, make_register_names(arch));
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);

  write_thread_start(handle.builder, 1, "main");

  write_instruction(handle.builder, 1, 1, 0x1000 + 0x10);

  w1::rewind::reg_write_record deltas{};
  deltas.sequence = 1;
  deltas.thread_id = 1;
  deltas.regfile_id = 0;
  deltas.entries = {make_reg_write_entry(0, 0x1111), make_reg_write_entry(1, 0x9000)};
  REQUIRE(handle.builder.emit_reg_write(deltas));

  write_memory_access(handle.builder, 1, 1, w1::rewind::mem_access_op::write, 0x2000, {0xDE, 0xAD});

  w1::rewind::memory_segment stack_segment{};
  stack_segment.space_id = 0;
  stack_segment.base = 0x3000;
  stack_segment.bytes = {0x10, 0x20};
  write_snapshot(
      handle.builder, 1, 1, {make_reg_write_entry(0, 0x2222), make_reg_write_entry(1, 0x3000)}, {stack_segment}
  );

  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(),
          redlog::get_logger("test.w1rewind.replay_state")
      )
  );

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::record_stream_cursor stream_cursor(stream);
  w1::rewind::flow_extractor extractor(&context);
  w1::rewind::history_window history(4);
  w1::rewind::flow_cursor cursor(std::move(stream_cursor), std::move(extractor), std::move(history), index);
  REQUIRE(cursor.open());

  w1::rewind::replay_state state;
  w1::rewind::replay_state_applier applier(context);
  w1::rewind::stateful_flow_cursor stateful_cursor(cursor, applier, state);
  REQUIRE(stateful_cursor.configure(context, true, true, nullptr));
  REQUIRE(cursor.seek(1, 1));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));

  const auto& state_view = stateful_cursor.state();
  CHECK(state_view.register_value(0, 0, w1::rewind::endian::little) == 0x2222);
  CHECK(state_view.register_value(0, 1, w1::rewind::endian::little) == 0x3000);

  auto mem_bytes = state_view.read_memory(0, 0x2000, 2);
  REQUIRE(mem_bytes.bytes.size() == 2);
  REQUIRE(mem_bytes.known.size() == 2);
  CHECK(mem_bytes.known[0] == 1);
  CHECK(mem_bytes.known[1] == 1);
  CHECK(std::to_integer<uint8_t>(mem_bytes.bytes[0]) == 0xDE);
  CHECK(std::to_integer<uint8_t>(mem_bytes.bytes[1]) == 0xAD);

  auto stack_bytes = state_view.read_memory(0, 0x3000, 2);
  REQUIRE(stack_bytes.bytes.size() == 2);
  REQUIRE(stack_bytes.known.size() == 2);
  CHECK(stack_bytes.known[0] == 1);
  CHECK(stack_bytes.known[1] == 1);
  CHECK(std::to_integer<uint8_t>(stack_bytes.bytes[0]) == 0x10);
  CHECK(std::to_integer<uint8_t>(stack_bytes.bytes[1]) == 0x20);

  auto unknown = state_view.read_memory(0, 0x2002, 1);
  REQUIRE(unknown.bytes.size() == 1);
  REQUIRE(unknown.known.size() == 1);
  CHECK(unknown.known[0] == 0);

  cursor.close();
  fs::remove(trace_path);
  fs::remove(index_path);
}
