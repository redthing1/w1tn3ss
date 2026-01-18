#include <filesystem>
#include <unordered_set>
#include <vector>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/rewind_tracer.hpp"
#include "w1tn3ss/runtime/rewind/trace_reader.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"
#include "w1tn3ss/tracer/trace_session.hpp"

namespace {

int rewind_block_test_worker(int count) {
  uint64_t buffer[8] = {2, 4, 6, 8, 10, 12, 14, 16};
  uint64_t total = 0;

  for (int i = 0; i < count; ++i) {
    uint64_t value = buffer[static_cast<size_t>(i) & 7u];
    total += value;
    buffer[static_cast<size_t>(i) & 7u] = value ^ total;
  }

  return static_cast<int>(total & 0xFFFFu);
}

} // namespace

TEST_CASE("w1rewind records block flow and snapshots") {
  namespace fs = std::filesystem;

  fs::path path = fs::temp_directory_path() / "w1rewind_recorder_blocks.trace";

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.recorder");

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1rewind::rewind_config config;
  config.output_path = path.string();
  config.record_instructions = false;
  config.record_register_deltas = false;
  config.snapshot_interval = 1;
  config.stack_snapshot_bytes = 0;
  config.memory.enabled = false;

  w1::trace_session_config session_config;
  session_config.instrumentation.include_modules = {"w1tn3ss_unit_tests"};
  session_config.thread_id = 1;
  session_config.thread_name = "unit_main";

  w1::trace_session<w1rewind::rewind_block_tracer> session(session_config, std::in_place, config, writer);

  if (!session.instrument()) {
    WARN("trace_session could not instrument modules; module scanning may be blocked");
    return;
  }

  std::vector<uint64_t> args;
  args.push_back(64);
  uint64_t result = 0;
  REQUIRE(session.call(reinterpret_cast<uint64_t>(&rewind_block_test_worker), args, &result));

  session.shutdown();
  writer->flush();
  writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  size_t block_exec_count = 0;
  size_t block_def_count = 0;
  size_t snapshot_count = 0;
  size_t thread_start_count = 0;
  size_t thread_end_count = 0;
  size_t instruction_count = 0;
  uint64_t last_sequence = 0;
  bool first_block = true;
  std::unordered_set<uint64_t> block_ids;
  std::unordered_set<uint64_t> block_sequences;

  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::block_definition_record>(record)) {
      const auto& def = std::get<w1::rewind::block_definition_record>(record);
      block_ids.insert(def.block_id);
      block_def_count += 1;
    } else if (std::holds_alternative<w1::rewind::block_exec_record>(record)) {
      const auto& exec = std::get<w1::rewind::block_exec_record>(record);
      if (first_block) {
        first_block = false;
      } else {
        CHECK(exec.sequence == last_sequence + 1);
      }
      last_sequence = exec.sequence;
      block_exec_count += 1;
      block_sequences.insert(exec.sequence);
      CHECK(block_ids.find(exec.block_id) != block_ids.end());
    } else if (std::holds_alternative<w1::rewind::snapshot_record>(record)) {
      const auto& snapshot = std::get<w1::rewind::snapshot_record>(record);
      CHECK(block_sequences.find(snapshot.sequence) != block_sequences.end());
      snapshot_count += 1;
    } else if (std::holds_alternative<w1::rewind::instruction_record>(record)) {
      instruction_count += 1;
    } else if (std::holds_alternative<w1::rewind::thread_start_record>(record)) {
      thread_start_count += 1;
    } else if (std::holds_alternative<w1::rewind::thread_end_record>(record)) {
      thread_end_count += 1;
    }
  }

  CHECK(reader.error().empty());
  CHECK(reader.header().version == w1::rewind::k_trace_version);
  CHECK((reader.header().flags & w1::rewind::trace_flag_blocks) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_instructions) == 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_register_deltas) == 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_memory_access) == 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_snapshots) != 0);
  CHECK(!reader.register_table().empty());
  CHECK(!reader.module_table().empty());
  CHECK(!reader.block_table().empty());

  CHECK(block_def_count > 0);
  CHECK(block_exec_count > 0);
  CHECK(instruction_count == 0);
  CHECK(snapshot_count > 0);
  CHECK(thread_start_count == 1);
  CHECK(thread_end_count == 1);
  CHECK(snapshot_count == block_exec_count / config.snapshot_interval);

  fs::remove(path);
}
