#include <filesystem>
#include <functional>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/flow_cursor.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"

namespace {

struct trace_bundle {
  std::filesystem::path trace_path;
  std::filesystem::path index_path;
  w1::rewind::trace_file_writer_config writer_config;
  std::shared_ptr<w1::rewind::trace_index> index;
  w1::rewind::replay_context context;
  std::shared_ptr<w1::rewind::trace_reader> stream;
};

trace_bundle build_instruction_trace(
    const char* name, size_t count, bool with_deltas, bool with_module = true, uint64_t thread_id = 1
) {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  trace_bundle out{};
  out.trace_path = temp_path(name);
  out.index_path = temp_path((std::string(name) + ".idx").c_str());

  out.writer_config.path = out.trace_path.string();
  out.writer_config.log = redlog::get_logger("test.w1rewind.cursor_semantics");
  out.writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(out.writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  if (with_deltas) {
    header.flags |= w1::rewind::trace_flag_register_deltas;
  }
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  if (with_module) {
    write_module_table(*writer, 1, 0x1000);
  }
  write_thread_start(*writer, thread_id, "thread1");

  for (uint64_t i = 0; i < count; ++i) {
    write_instruction(*writer, thread_id, i, 0x1000 + 0x10 + i * 4);
    if (with_deltas) {
      write_register_delta(*writer, thread_id, i, 0, 0x1000 + i);
    }
  }

  write_thread_end(*writer, thread_id);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  out.index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          out.trace_path.string(), out.index_path.string(), index_options, out.index.get(), out.writer_config.log
      )
  );

  std::string error;
  REQUIRE(w1::rewind::load_replay_context(out.trace_path.string(), out.context, error));
  out.stream = std::make_shared<w1::rewind::trace_reader>(out.trace_path.string());

  return out;
}

trace_bundle build_block_trace(const char* name, size_t count, uint64_t thread_id = 1) {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  trace_bundle out{};
  out.trace_path = temp_path(name);
  out.index_path = temp_path((std::string(name) + ".idx").c_str());

  out.writer_config.path = out.trace_path.string();
  out.writer_config.log = redlog::get_logger("test.w1rewind.cursor_semantics");
  out.writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(out.writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("x86_64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_blocks;
  REQUIRE(writer->write_header(header));

  write_basic_metadata(*writer, header.arch, minimal_registers(header.arch));
  write_module_table(*writer, 1, 0x5000);
  write_thread_start(*writer, thread_id, "thread1");

  for (uint64_t i = 0; i < count; ++i) {
    write_block_def(*writer, i + 1, 0x5000 + 0x10 + i * 0x10, 4);
    write_block_exec(*writer, thread_id, i, i + 1);
  }

  write_thread_end(*writer, thread_id);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  out.index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          out.trace_path.string(), out.index_path.string(), index_options, out.index.get(), out.writer_config.log
      )
  );

  std::string error;
  REQUIRE(w1::rewind::load_replay_context(out.trace_path.string(), out.context, error));
  out.stream = std::make_shared<w1::rewind::trace_reader>(out.trace_path.string());

  return out;
}

} // namespace

TEST_CASE("w1rewind replay cursor reports begin/end of trace errors") {
  auto trace = build_instruction_trace("w1rewind_replay_bounds.trace", 1, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 0);

  CHECK_FALSE(cursor.step_backward(step));
  CHECK(cursor.error_kind() == w1::rewind::flow_error_kind::begin_of_trace);

  CHECK_FALSE(cursor.step_forward(step));
  CHECK(cursor.error_kind() == w1::rewind::flow_error_kind::end_of_trace);
}

TEST_CASE("w1rewind replay cursor shrinks history without losing position") {
  auto trace = build_instruction_trace("w1rewind_replay_history_resize.trace", 6, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 5;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  for (uint64_t i = 0; i <= 4; ++i) {
    REQUIRE(cursor.step_forward(step));
    CHECK(step.sequence == i);
  }

  cursor.set_history_size(2);

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 3);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 2);
}

TEST_CASE("w1rewind replay cursor handles history size one") {
  auto trace = build_instruction_trace("w1rewind_replay_history_one.trace", 3, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 1;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 1);
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 2);

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 1);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 0);
}

TEST_CASE("w1rewind replay cursor seek fails for missing thread") {
  auto trace = build_instruction_trace("w1rewind_replay_missing_thread.trace", 2, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  CHECK_FALSE(cursor.seek(2, 0));
  CHECK(cursor.error() == "no anchor for thread");
}

TEST_CASE("w1rewind replay cursor seek_from_location resets to prior step") {
  auto trace = build_instruction_trace("w1rewind_replay_seek_location.trace", 3, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  w1::rewind::trace_record_location loc{};
  REQUIRE(cursor.step_forward(step, &loc));
  CHECK(step.sequence == 0);

  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 1);

  REQUIRE(cursor.seek_from_location(1, 0, loc));
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 0);
}

TEST_CASE("w1rewind replay cursor can cancel during seek") {
  auto trace = build_instruction_trace("w1rewind_replay_cancel_seek.trace", 2, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  cursor.set_cancel_checker([]() { return true; });
  REQUIRE(cursor.open());
  CHECK_FALSE(cursor.seek(1, 0));
  CHECK(cursor.error() == "cancelled");
}

TEST_CASE("w1rewind replay cursor can cancel during observer consume") {
  auto trace = build_instruction_trace("w1rewind_replay_cancel_consume.trace", 2, true);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  struct noop_observer final : public w1::rewind::flow_record_observer {
    bool on_record(const w1::rewind::trace_record&, uint64_t, std::string&) override { return true; }
  } observer;
  cursor.set_observer(&observer);

  auto counter = std::make_shared<int>(0);
  cursor.set_cancel_checker([counter]() {
    (*counter)++;
    return *counter > 1;
  });

  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  CHECK_FALSE(cursor.step_forward(step));
  CHECK(cursor.error() == "cancelled");
}

TEST_CASE("w1rewind replay cursor history-only stays consistent across back/forward") {
  auto trace = build_instruction_trace("w1rewind_replay_history_consistent.trace", 6, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 3;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  for (uint64_t i = 0; i <= 3; ++i) {
    REQUIRE(cursor.step_forward(step));
    CHECK(step.sequence == i);
  }

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 2);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 1);

  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 2);
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 3);

  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 4);
}

TEST_CASE("w1rewind replay cursor supports history-disabled backward stepping") {
  auto trace = build_instruction_trace("w1rewind_replay_history_disabled.trace", 4, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  cursor.set_history_enabled(false);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 2);

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 1);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 0);

  CHECK_FALSE(cursor.step_backward(step));
  CHECK(cursor.error_kind() == w1::rewind::flow_error_kind::begin_of_trace);
}

TEST_CASE("w1rewind replay cursor cancels during backward prefill") {
  auto trace = build_instruction_trace("w1rewind_replay_cancel_prefill.trace", 3, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 2;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));

  cursor.set_cancel_checker([]() { return true; });
  CHECK_FALSE(cursor.step_backward(step));
  CHECK(cursor.error() == "cancelled");
}

TEST_CASE("w1rewind replay cursor errors when stepping without seek") {
  auto trace = build_instruction_trace("w1rewind_replay_no_seek.trace", 1, false);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 4;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());

  w1::rewind::flow_step step{};
  CHECK_FALSE(cursor.step_forward(step));
  CHECK(cursor.error() == "thread not selected");

  CHECK_FALSE(cursor.step_backward(step));
  CHECK(cursor.error() == "no current position");
}

TEST_CASE("w1rewind replay cursor supports block flow backward prefill") {
  auto trace = build_block_trace("w1rewind_replay_block_backward.trace", 3);

  w1::rewind::flow_cursor_config replay_config{};
  replay_config.stream = trace.stream;
  replay_config.index = trace.index;
  replay_config.history_size = 2;
  replay_config.context = &trace.context;

  w1::rewind::flow_cursor cursor(replay_config);
  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  REQUIRE(cursor.step_forward(step));
  CHECK(step.sequence == 2);
  CHECK(step.is_block);

  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 1);
  REQUIRE(cursor.step_backward(step));
  CHECK(step.sequence == 0);
}
