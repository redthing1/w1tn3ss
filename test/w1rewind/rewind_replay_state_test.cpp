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
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

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
  fs::path index_path = temp_path("w1rewind_replay_state.trace.idx");

  w1::rewind::trace_file_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.replay_state");
  config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.arch = w1::arch::detect_host_arch_spec();
  header.flags = w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_register_deltas |
                 w1::rewind::trace_flag_memory_access | w1::rewind::trace_flag_memory_values |
                 w1::rewind::trace_flag_snapshots | w1::rewind::trace_flag_stack_snapshot;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, make_register_names(header.arch));
  write_module_table(*writer, 1, 0x1000);

  write_thread_start(*writer, 1, "main");

  write_instruction(*writer, 1, 1, 0x1000 + 0x10);

  w1::rewind::register_delta_record deltas{};
  deltas.sequence = 1;
  deltas.thread_id = 1;
  deltas.deltas = {
      w1::rewind::register_delta{0, 0x1111},
      w1::rewind::register_delta{1, 0x9000},
  };
  REQUIRE(writer->write_register_deltas(deltas));

  w1::rewind::memory_access_record mem{};
  mem.sequence = 1;
  mem.thread_id = 1;
  mem.kind = w1::rewind::memory_access_kind::write;
  mem.address = 0x2000;
  mem.size = 2;
  mem.value_known = true;
  mem.data = {0xDE, 0xAD};
  REQUIRE(writer->write_memory_access(mem));

  w1::rewind::snapshot_record snapshot{};
  snapshot.snapshot_id = 1;
  snapshot.sequence = 1;
  snapshot.thread_id = 1;
  snapshot.registers = {
      w1::rewind::register_delta{0, 0x2222},
      w1::rewind::register_delta{1, 0x3000},
  };
  w1::rewind::stack_segment stack_segment{};
  stack_segment.base = 0x3000;
  stack_segment.size = 2;
  stack_segment.bytes = {0x10, 0x20};
  snapshot.stack_segments.push_back(std::move(stack_segment));
  snapshot.reason = "test";
  REQUIRE(writer->write_snapshot(snapshot));

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), config.log));

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = stream;
  replay_config.index = index;
  replay_config.history_size = 4;
  replay_config.context = &context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());

  w1::rewind::replay_state state;
  w1::rewind::replay_state_applier applier(context);
  w1::rewind::stateful_flow_cursor stateful_cursor(cursor, applier, state);
  stateful_cursor.configure(context, true, true);
  REQUIRE(cursor.seek(1, 1));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));

  const auto& state_view = stateful_cursor.state();
  CHECK(state_view.register_value(0) == 0x2222);
  CHECK(state_view.register_value(1) == 0x3000);

  auto mem_bytes = state_view.read_memory(0x2000, 2);
  REQUIRE(mem_bytes.bytes.size() == 2);
  REQUIRE(mem_bytes.known.size() == 2);
  CHECK(mem_bytes.known[0] == 1);
  CHECK(mem_bytes.known[1] == 1);
  CHECK(std::to_integer<uint8_t>(mem_bytes.bytes[0]) == 0xDE);
  CHECK(std::to_integer<uint8_t>(mem_bytes.bytes[1]) == 0xAD);

  auto stack_bytes = state_view.read_memory(0x3000, 2);
  REQUIRE(stack_bytes.bytes.size() == 2);
  REQUIRE(stack_bytes.known.size() == 2);
  CHECK(stack_bytes.known[0] == 1);
  CHECK(stack_bytes.known[1] == 1);
  CHECK(std::to_integer<uint8_t>(stack_bytes.bytes[0]) == 0x10);
  CHECK(std::to_integer<uint8_t>(stack_bytes.bytes[1]) == 0x20);

  auto unknown = state_view.read_memory(0x2002, 1);
  REQUIRE(unknown.bytes.size() == 1);
  REQUIRE(unknown.known.size() == 1);
  CHECK(unknown.known[0] == 0);

  cursor.close();
  fs::remove(trace_path);
  fs::remove(index_path);
}
