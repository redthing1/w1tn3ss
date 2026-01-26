#include <random>

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
  std::shared_ptr<w1::rewind::trace_index> index;
  w1::rewind::replay_context context;
  std::shared_ptr<w1::rewind::trace_reader> stream;
};

w1::rewind::flow_cursor make_flow_cursor(trace_bundle& bundle, size_t history_size) {
  w1::rewind::record_stream_cursor stream_cursor(bundle.stream);
  w1::rewind::flow_extractor extractor(&bundle.context);
  w1::rewind::history_window history(history_size);
  return w1::rewind::flow_cursor(std::move(stream_cursor), std::move(extractor), std::move(history), bundle.index);
}

trace_bundle build_instruction_trace(const char* name, uint64_t count) {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  trace_bundle out;
  out.trace_path = temp_path(name);
  out.index_path = temp_path((std::string(name) + ".w1ridx").c_str());
  auto logger = redlog::get_logger("test.w1rewind.cursor_property");
  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(out.trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 1, 0x1000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");

  for (uint64_t i = 0; i < count; ++i) {
    write_instruction(handle.builder, 1, i, 0x1000 + i * 4);
  }

  write_thread_end(handle.builder, 1);
  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options options;
  out.index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(out.trace_path.string(), out.index_path.string(), options, out.index.get(), logger)
  );

  std::string error;
  REQUIRE(w1::rewind::load_replay_context(out.trace_path.string(), out.context, error));
  out.stream = std::make_shared<w1::rewind::trace_reader>(out.trace_path.string());
  return out;
}

trace_bundle build_block_trace(const char* name, uint64_t count) {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  trace_bundle out;
  out.trace_path = temp_path(name);
  out.index_path = temp_path((std::string(name) + ".w1ridx").c_str());
  auto logger = redlog::get_logger("test.w1rewind.cursor_property");
  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(out.trace_path, header, logger);

  write_basic_metadata(handle.builder, "x86_64", arch, minimal_registers(arch));
  write_image_mapping(handle.builder, 1, 0x2000, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");

  for (uint64_t i = 0; i < count; ++i) {
    write_block_def(handle.builder, i + 1, 0x2000 + i * 8, 4);
    write_block_exec(handle.builder, 1, i, i + 1);
  }

  write_thread_end(handle.builder, 1);
  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options options;
  out.index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(out.trace_path.string(), out.index_path.string(), options, out.index.get(), logger)
  );

  std::string error;
  REQUIRE(w1::rewind::load_replay_context(out.trace_path.string(), out.context, error));
  out.stream = std::make_shared<w1::rewind::trace_reader>(out.trace_path.string());
  return out;
}

void run_random_walk(w1::rewind::flow_cursor& cursor, uint64_t count, uint32_t seed) {
  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> pick(0, 1);

  REQUIRE(cursor.open());
  REQUIRE(cursor.seek(1, 0));

  w1::rewind::flow_step step{};
  REQUIRE(cursor.step_forward(step));
  uint64_t model = 0;
  CHECK(step.sequence == model);

  for (size_t i = 0; i < 200; ++i) {
    bool forward = pick(rng) == 1;
    if (forward && model + 1 < count) {
      REQUIRE(cursor.step_forward(step));
      model += 1;
      CHECK(step.sequence == model);
    } else if (!forward && model > 0) {
      REQUIRE(cursor.step_backward(step));
      model -= 1;
      CHECK(step.sequence == model);
    } else if (forward && model + 1 >= count) {
      CHECK_FALSE(cursor.step_forward(step));
      CHECK(cursor.error_kind() == w1::rewind::flow_error_kind::end_of_trace);
    } else if (!forward && model == 0) {
      CHECK_FALSE(cursor.step_backward(step));
      CHECK(cursor.error_kind() == w1::rewind::flow_error_kind::begin_of_trace);
    }
  }
}

} // namespace

TEST_CASE("w1rewind replay cursor random walk on instruction trace") {
  auto trace = build_instruction_trace("w1rewind_cursor_property_inst.trace", 12);
  auto cursor = make_flow_cursor(trace, 4);
  run_random_walk(cursor, 12, 1337);
}

TEST_CASE("w1rewind replay cursor random walk on block trace") {
  auto trace = build_block_trace("w1rewind_cursor_property_block.trace", 10);
  auto cursor = make_flow_cursor(trace, 3);
  run_random_walk(cursor, 10, 4242);
}
