#include <filesystem>
#include <memory>
#include <string>
#include <variant>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/flow_cursor.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

TEST_CASE("w1rewind replay cursor steps through instruction flow") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_inst.trace");
  fs::path index_path = temp_path("w1rewind_replay_inst.trace.idx");

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_module_table(*writer, 1, 0x1000);
  write_thread_start(*writer, 1, "thread1");
  write_thread_start(*writer, 2, "thread2");

  for (uint64_t i = 0; i < 4; ++i) {
    write_instruction(*writer, 1, i, 0x1000 + 0x10 + i * 4);
    if (i < 2) {
      write_instruction(*writer, 2, i, 0x1000 + 0x40 + i * 4);
    }
  }

  write_thread_end(*writer, 1);
  write_thread_end(*writer, 2);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(), writer_config.log
      )
  );

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

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_module_table(*writer, 7, 0x2000);
  write_thread_start(*writer, 1, "thread1");

  write_block_def(*writer, 1, 0x2000 + 0x10, 4);
  write_block_def(*writer, 2, 0x2000 + 0x20, 4);
  write_block_exec(*writer, 1, 0, 1);
  write_block_exec(*writer, 1, 1, 2);

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(), writer_config.log
      )
  );

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

TEST_CASE("w1rewind replay cursor handles module-less traces") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_moduleless.trace");
  fs::path index_path = temp_path("w1rewind_replay_moduleless.trace.idx");

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, 0x4000);
  write_instruction(*writer, 1, 1, 0x4004);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(), writer_config.log
      )
  );

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
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 0);
  CHECK(step.address == 0x4000);
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 1);
  CHECK(step.address == 0x4004);
}

struct cursor_delta_observer final : public w1::rewind::flow_record_observer {
  size_t delta_count = 0;

  bool on_record(const w1::rewind::trace_record& record, uint64_t, std::string&) override {
    if (std::holds_alternative<w1::rewind::register_delta_record>(record)) {
      delta_count += 1;
    }
    return true;
  }
};

TEST_CASE("w1rewind replay cursor backfills history window when stepping backward") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_history.trace");
  fs::path index_path = temp_path("w1rewind_replay_history.trace.idx");

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_module_table(*writer, 1, 0x1000);
  write_thread_start(*writer, 1, "thread1");

  for (uint64_t i = 0; i < 8; ++i) {
    write_instruction(*writer, 1, i, 0x1000 + 0x10 + i * 4);
  }

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(), writer_config.log
      )
  );

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = stream;
  replay_config.index = index;
  replay_config.history_size = 3;
  replay_config.context = &context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  for (uint64_t i = 0; i <= 6; ++i) {
    REQUIRE(cursor.step_forward(step));
    CHECK(step.sequence == i);
  }

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 5);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 4);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 3);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 2);
}

TEST_CASE("w1rewind replay cursor supports history with observer") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_observer.trace");
  fs::path index_path = temp_path("w1rewind_replay_observer.trace.idx");

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_module_table(*writer, 1, 0x2000);
  write_thread_start(*writer, 1, "thread1");

  for (uint64_t i = 0; i < 4; ++i) {
    write_instruction(*writer, 1, i, 0x2000 + 0x10 + i * 4);
    write_register_delta(*writer, 1, i, 0, 0x1000 + i);
  }

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(), writer_config.log
      )
  );

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
  cursor_delta_observer observer;
  cursor.set_observer(&observer);

  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_backward(step));
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));

  CHECK(observer.delta_count == 4);
}

TEST_CASE("w1rewind replay cursor cancels during forward step") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_replay_cancel.trace");
  fs::path index_path = temp_path("w1rewind_replay_cancel.trace.idx");

  w1::rewind::trace_file_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.replay");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_thread_start(*writer, 1, "thread1");

  for (uint64_t i = 0; i < 3; ++i) {
    write_instruction(*writer, 1, i, 0x3000 + 0x10 + i * 4);
  }

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(), writer_config.log
      )
  );

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
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));

  cursor.set_cancel_checker([]() { return true; });
  CHECK_FALSE(cursor.step_forward(step));
  CHECK(cursor.error_kind() == w1::rewind::flow_error_kind::other);
  CHECK(cursor.error() == "cancelled");
}
