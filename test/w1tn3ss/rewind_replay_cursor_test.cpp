#include <filesystem>

#include "doctest/doctest.hpp"

#include "rewind_test_helpers.hpp"
#include "w1tn3ss/runtime/rewind/replay_flow_cursor.hpp"
#include "w1tn3ss/runtime/rewind/trace_index.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"

TEST_CASE("w1rewind replay cursor steps through instruction flow") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_inst.trace");
  fs::path index_path = temp_path("w1rewind_replay_inst.trace.idx");

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
  write_thread_start(*writer, 1, "thread1");
  write_thread_start(*writer, 2, "thread2");

  for (uint64_t i = 0; i < 4; ++i) {
    write_instruction(*writer, 1, i, 1, 0x10 + i * 4);
    if (i < 2) {
      write_instruction(*writer, 2, i, 1, 0x40 + i * 4);
    }
  }

  write_thread_end(*writer, 1);
  write_thread_end(*writer, 2);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_flow_cursor cursor({trace_path.string(), index_path.string(), 4});
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
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_block.trace");
  fs::path index_path = temp_path("w1rewind_replay_block.trace.idx");

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
  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 7, 0x10, 4);
  write_block_def(*writer, 2, 7, 0x20, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_block_exec(*writer, 1, 1, 2);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  w1::rewind::trace_index index;
  REQUIRE(w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, &index, writer_config.log));

  w1::rewind::replay_flow_cursor cursor({trace_path.string(), index_path.string(), 4});
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
