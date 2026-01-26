#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

TEST_CASE("replay context rejects trace without metadata") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_minimal_context.trace");

  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.minimal"));

  write_thread_start(handle.builder, 1, "main");
  write_instruction(handle.builder, 1, 0, 0x1000);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::replay_context context;
  std::string error;
  CHECK_FALSE(w1::rewind::load_replay_context(trace_path.string(), context, error));
  CHECK(!error.empty());
}

TEST_CASE("replay session tracks memory without register specs") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_minimal_memory.trace");
  fs::path index_path = temp_path("w1rewind_minimal_memory.trace.w1ridx");

  auto arch = parse_arch_or_fail("x86_64");
  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1rewind.minimal"));

  REQUIRE(handle.builder.emit_arch_descriptor(make_arch_descriptor("x86_64", arch)));
  REQUIRE(handle.builder.emit_environment(make_environment()));
  REQUIRE(handle.builder.emit_address_space(make_address_space(0, arch)));

  write_thread_start(handle.builder, 1, "main");
  write_instruction(handle.builder, 1, 1, 0x1000);
  write_memory_access(handle.builder, 1, 1, w1::rewind::mem_access_op::write, 0x2000, {0xAA, 0xBB});
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(
          trace_path.string(), index_path.string(), index_options, index.get(),
          redlog::get_logger("test.w1rewind.minimal")
      )
  );

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));

  auto stream = std::make_shared<w1::rewind::trace_reader>(trace_path.string());
  w1::rewind::replay_session_config session_config{};
  session_config.stream = stream;
  session_config.index = index;
  session_config.context = context;
  session_config.thread_id = 1;
  session_config.start_sequence = 1;
  session_config.track_registers = false;
  session_config.track_memory = true;

  w1::rewind::replay_session session(session_config);
  bool opened = session.open();
  INFO(session.error());
  REQUIRE(opened);
  REQUIRE(session.step_flow());

  auto bytes = session.read_memory(0x2000, 2);
  REQUIRE(bytes.bytes.size() == 2);
  REQUIRE(bytes.known.size() == 2);
  CHECK(bytes.known[0] == 1);
  CHECK(bytes.known[1] == 1);
  CHECK(std::to_integer<uint8_t>(bytes.bytes[0]) == 0xAA);
  CHECK(std::to_integer<uint8_t>(bytes.bytes[1]) == 0xBB);
}
