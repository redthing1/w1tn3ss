#include <filesystem>

#include "doctest/doctest.hpp"

#include "w1tn3ss/runtime/rewind/replay_cursor.hpp"
#include "w1tn3ss/runtime/rewind/trace_index.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"

namespace {

void write_module_table(w1::rewind::trace_writer& writer, uint64_t module_id, uint64_t base) {
  w1::rewind::module_record module{};
  module.id = module_id;
  module.base = base;
  module.size = 0x1000;
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
    uint64_t module_id,
    uint64_t module_offset
) {
  w1::rewind::instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.module_id = module_id;
  record.module_offset = module_offset;
  record.size = 4;
  record.flags = 0;
  REQUIRE(writer.write_instruction(record));
}

void write_block_def(
    w1::rewind::trace_writer& writer,
    uint64_t block_id,
    uint64_t module_id,
    uint64_t module_offset,
    uint32_t size
) {
  w1::rewind::block_definition_record record{};
  record.block_id = block_id;
  record.module_id = module_id;
  record.module_offset = module_offset;
  record.size = size;
  REQUIRE(writer.write_block_definition(record));
}

void write_block_exec(
    w1::rewind::trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint64_t block_id
) {
  w1::rewind::block_exec_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.block_id = block_id;
  REQUIRE(writer.write_block_exec(record));
}

} // namespace

TEST_CASE("w1rewind replay cursor steps through instruction flow") {
  namespace fs = std::filesystem;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_replay_inst.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_replay_inst.trace.idx";

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_module_table(*writer, 1, 0x1000);

  w1::rewind::thread_start_record start1{};
  start1.thread_id = 1;
  start1.name = "thread1";
  REQUIRE(writer->write_thread_start(start1));

  w1::rewind::thread_start_record start2{};
  start2.thread_id = 2;
  start2.name = "thread2";
  REQUIRE(writer->write_thread_start(start2));

  for (uint64_t i = 0; i < 4; ++i) {
    write_instruction(*writer, 1, i, 1, 0x10 + i * 4);
    if (i < 2) {
      write_instruction(*writer, 2, i, 1, 0x40 + i * 4);
    }
  }

  w1::rewind::thread_end_record end1{};
  end1.thread_id = 1;
  REQUIRE(writer->write_thread_end(end1));

  w1::rewind::thread_end_record end2{};
  end2.thread_id = 2;
  REQUIRE(writer->write_thread_end(end2));

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_cursor cursor({trace_path.string(), index_path.string(), 4});
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 2));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  CHECK(step.thread_id == 1);
  CHECK(step.sequence == 2);
  CHECK(step.address == 0x1000 + 0x10 + 2 * 4);

  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 3);

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 2);
}

TEST_CASE("w1rewind replay cursor resolves block flow addresses") {
  namespace fs = std::filesystem;

  fs::path trace_path = fs::temp_directory_path() / "w1rewind_replay_block.trace";
  fs::path index_path = fs::temp_directory_path() / "w1rewind_replay_block.trace.idx";

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_module_table(*writer, 7, 0x2000);

  w1::rewind::thread_start_record start{};
  start.thread_id = 1;
  start.name = "thread1";
  REQUIRE(writer->write_thread_start(start));

  write_block_def(*writer, 1, 7, 0x10, 4);
  write_block_def(*writer, 2, 7, 0x20, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_block_exec(*writer, 1, 1, 2);

  w1::rewind::thread_end_record end{};
  end.thread_id = 1;
  REQUIRE(writer->write_thread_end(end));

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_cursor cursor({trace_path.string(), index_path.string(), 4});
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 0);
  CHECK(step.is_block);
  CHECK(step.address == 0x2000 + 0x10);

  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 1);
  CHECK(step.address == 0x2000 + 0x20);
}
