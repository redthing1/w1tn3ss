#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1rewind/rewind_test_helpers.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/replay_session.hpp"
#include "w1rewind/trace/trace_file_writer.hpp"
#include "w1rewind/trace/trace_index.hpp"
#include "w1rewind/trace/trace_reader.hpp"

TEST_CASE("replay context loads minimal trace without metadata") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_minimal_context.trace");

  w1::rewind::trace_file_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.minimal");
  config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("arm64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_thread_start(*writer, 1, "main");
  write_instruction(*writer, 1, 0, 0x1000);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::replay_context context;
  std::string error;
  REQUIRE(w1::rewind::load_replay_context(trace_path.string(), context, error));
  CHECK(!context.target_info.has_value());
  CHECK(!context.target_environment.has_value());
  CHECK(context.register_specs.empty());
  CHECK(context.register_names.empty());
  CHECK(context.threads.size() == 1);

  auto features = context.features();
  CHECK(!features.has_registers);
  CHECK(!features.track_memory);
}

TEST_CASE("replay session tracks memory without register specs") {
  namespace fs = std::filesystem;
  using namespace w1::rewind::test_helpers;

  fs::path trace_path = temp_path("w1rewind_minimal_memory.trace");
  fs::path index_path = temp_path("w1rewind_minimal_memory.trace.idx");

  w1::rewind::trace_file_writer_config config;
  config.path = trace_path.string();
  config.log = redlog::get_logger("test.w1rewind.minimal");
  config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_file_writer(config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  auto arch = parse_arch_or_fail("arm64");
  w1::rewind::trace_header header{};
  header.arch = arch;
  header.flags =
      w1::rewind::trace_flag_instructions | w1::rewind::trace_flag_memory_access | w1::rewind::trace_flag_memory_values;
  REQUIRE(writer->write_header(header));

  write_thread_start(*writer, 1, "main");
  write_instruction(*writer, 1, 1, 0x1000);

  w1::rewind::memory_access_record mem{};
  mem.sequence = 1;
  mem.thread_id = 1;
  mem.kind = w1::rewind::memory_access_kind::write;
  mem.address = 0x2000;
  mem.size = 2;
  mem.value_known = true;
  mem.data = {0xAA, 0xBB};
  REQUIRE(writer->write_memory_access(mem));

  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();

  w1::rewind::trace_index_options index_options;
  auto index = std::make_shared<w1::rewind::trace_index>();
  REQUIRE(
      w1::rewind::build_trace_index(trace_path.string(), index_path.string(), index_options, index.get(), config.log)
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
