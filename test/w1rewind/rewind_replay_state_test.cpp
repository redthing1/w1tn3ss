#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/replay_flow_cursor.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/trace_index.hpp"
#include "w1rewind/record/trace_writer.hpp"

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

  w1::rewind::trace_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.replay_state");
  config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(config);
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
  snapshot.stack_snapshot = {0x10, 0x20};
  snapshot.reason = "test";
  REQUIRE(writer->write_snapshot(snapshot));

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, config.log));

  w1::rewind::replay_flow_cursor_config replay_config{};
  replay_config.trace_path = trace_path.string();
  replay_config.index_path = index_path.string();
  replay_config.history_size = 4;
  replay_config.track_registers = true;
  replay_config.track_memory = true;

  w1::rewind::replay_flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 1));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));

  const auto* state = cursor.state();
  REQUIRE(state != nullptr);
  CHECK(state->register_value(0) == 0x2222);
  CHECK(state->register_value(1) == 0x3000);

  auto mem_bytes = state->read_memory(0x2000, 2);
  REQUIRE(mem_bytes.size() == 2);
  CHECK(mem_bytes[0].has_value());
  CHECK(mem_bytes[1].has_value());
  CHECK(mem_bytes[0].value() == 0xDE);
  CHECK(mem_bytes[1].value() == 0xAD);

  auto stack_layout = w1::rewind::compute_stack_snapshot_layout(0x3000, 2);
  auto stack_bytes = state->read_memory(stack_layout.base, 2);
  REQUIRE(stack_bytes.size() == 2);
  CHECK(stack_bytes[0].has_value());
  CHECK(stack_bytes[1].has_value());
  CHECK(stack_bytes[0].value() == 0x10);
  CHECK(stack_bytes[1].value() == 0x20);

  auto unknown = state->read_memory(0x2002, 1);
  REQUIRE(unknown.size() == 1);
  CHECK(!unknown[0].has_value());

  fs::remove(trace_path);
  fs::remove(index_path);
}
