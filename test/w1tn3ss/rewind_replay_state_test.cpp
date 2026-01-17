#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1tn3ss/runtime/rewind/replay_cursor.hpp"
#include "w1tn3ss/runtime/rewind/trace_index.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"

namespace {

std::filesystem::path make_temp_path(const char* name) {
  return std::filesystem::temp_directory_path() / name;
}

std::vector<std::string> make_register_names(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86_64:
    return {"rax", "rsp"};
  case w1::rewind::trace_arch::x86:
    return {"eax", "esp"};
  case w1::rewind::trace_arch::aarch64:
  case w1::rewind::trace_arch::arm:
    return {"x0", "sp"};
  default:
    break;
  }
  return {"r0", "sp"};
}

void write_module_table(w1::rewind::trace_writer& writer) {
  w1::rewind::module_record module{};
  module.id = 1;
  module.base = 0x1000;
  module.size = 0x2000;
  module.permissions = 5;
  module.path = "test_module";

  w1::rewind::module_table_record table{};
  table.modules.push_back(module);
  REQUIRE(writer.write_module_table(table));
}

void write_instruction(
    w1::rewind::trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint64_t module_offset
) {
  w1::rewind::instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.module_id = 1;
  record.module_offset = module_offset;
  record.size = 4;
  record.flags = 0;
  REQUIRE(writer.write_instruction(record));
}

} // namespace

TEST_CASE("w1rewind replay cursor applies register and memory state") {
  namespace fs = std::filesystem;

  fs::path trace_path = make_temp_path("w1rewind_replay_state.trace");
  fs::path index_path = make_temp_path("w1rewind_replay_state.trace.idx");

  w1::rewind::trace_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.replay_state");
  config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = w1::rewind::detect_trace_arch();
  header.pointer_size = w1::rewind::detect_pointer_size();
  header.flags = w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_register_deltas |
                 w1::rewind::trace_flag_memory_access | w1::rewind::trace_flag_memory_values |
                 w1::rewind::trace_flag_boundaries | w1::rewind::trace_flag_stack_window;
  REQUIRE(writer->write_header(header));

  w1::rewind::register_table_record reg_table{};
  reg_table.names = make_register_names(header.architecture);
  REQUIRE(writer->write_register_table(reg_table));

  write_module_table(*writer);

  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "main";
  REQUIRE(writer->write_thread_start(start));

  write_instruction(*writer, 1, 1, 0x10);

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

  w1::rewind::boundary_record boundary{};
  boundary.boundary_id = 1;
  boundary.sequence = 1;
  boundary.thread_id = 1;
  boundary.registers = {
      w1::rewind::register_delta{0, 0x2222},
      w1::rewind::register_delta{1, 0x3000},
  };
  boundary.stack_window = {0x10, 0x20};
  boundary.reason = "test";
  REQUIRE(writer->write_boundary(boundary));

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  REQUIRE(writer->write_thread_end(end));

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, config.log));

  w1::rewind::replay_cursor_config replay_config{};
  replay_config.trace_path = trace_path.string();
  replay_config.index_path = index_path.string();
  replay_config.history_size = 4;
  replay_config.track_registers = true;
  replay_config.track_memory = true;

  w1::rewind::replay_cursor cursor(replay_config);
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

  auto stack_bytes = state->read_memory(0x3000, 2);
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
