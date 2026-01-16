#include <filesystem>
#include <unordered_set>
#include <vector>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/rewind_tracer.hpp"
#include "w1tn3ss/runtime/rewind/trace_reader.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"
#include "w1tn3ss/tracer/trace_session.hpp"

namespace {

int rewind_test_worker(int count) {
  uint64_t buffer[8] = {1, 3, 5, 7, 11, 13, 17, 19};
  uint64_t total = 0;

  for (int i = 0; i < count; ++i) {
    uint64_t value = buffer[static_cast<size_t>(i) & 7u];
    total += value;
    buffer[static_cast<size_t>(i) & 7u] = value ^ total;
  }

  return static_cast<int>(total & 0xFFFFu);
}

} // namespace

TEST_CASE("w1rewind records instruction flow, memory, and boundaries") {
  namespace fs = std::filesystem;

  fs::path path = fs::temp_directory_path() / "w1rewind_recorder_recording.trace";

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = path.string();
  writer_config.log = redlog::get_logger("test.w1rewind.recorder");

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1rewind::rewind_config config;
  config.output_path = path.string();
  config.record_instructions = true;
  config.record_register_deltas = true;
  config.boundary_interval = 8;
  config.stack_window_bytes = 0;
  config.memory.enabled = true;
  config.memory.include_reads = true;
  config.memory.include_values = true;
  config.memory.max_value_bytes = 4;

  w1::trace_session_config session_config;
  session_config.instrumentation.include_modules = {"w1tn3ss_unit_tests"};
  session_config.thread_id = 1;
  session_config.thread_name = "unit_main";

  w1::trace_session<w1rewind::rewind_instruction_tracer> session(session_config, std::in_place, config, writer);

  if (!session.instrument()) {
    WARN("trace_session could not instrument modules; module scanning may be blocked");
    return;
  }

  std::vector<uint64_t> args;
  args.push_back(64);
  uint64_t result = 0;
  REQUIRE(session.call(reinterpret_cast<uint64_t>(&rewind_test_worker), args, &result));

  session.shutdown();
  writer->flush();
  writer->close();

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  size_t instruction_count = 0;
  size_t delta_count = 0;
  size_t memory_count = 0;
  size_t boundary_count = 0;
  size_t thread_start_count = 0;
  size_t thread_end_count = 0;
  bool saw_truncated = false;
  bool first_instruction = true;
  uint64_t last_sequence = 0;
  std::unordered_set<uint64_t> instruction_sequences;
  const uint32_t memory_max_bytes = config.memory.max_value_bytes;

  w1::rewind::trace_record record;
  while (reader.read_next(record)) {
    if (std::holds_alternative<w1::rewind::instruction_record>(record)) {
      const auto& inst = std::get<w1::rewind::instruction_record>(record);
      if (first_instruction) {
        first_instruction = false;
      } else {
        CHECK(inst.sequence == last_sequence + 1);
      }
      last_sequence = inst.sequence;
      instruction_sequences.insert(inst.sequence);
      instruction_count += 1;
    } else if (std::holds_alternative<w1::rewind::register_delta_record>(record)) {
      const auto& deltas = std::get<w1::rewind::register_delta_record>(record);
      CHECK(instruction_sequences.find(deltas.sequence) != instruction_sequences.end());
      delta_count += 1;
    } else if (std::holds_alternative<w1::rewind::memory_access_record>(record)) {
      const auto& mem = std::get<w1::rewind::memory_access_record>(record);
      CHECK(instruction_sequences.find(mem.sequence) != instruction_sequences.end());
      if (mem.size > memory_max_bytes) {
        CHECK(mem.value_truncated);
        saw_truncated = true;
      }
      if (mem.value_known) {
        CHECK(!mem.data.empty());
        CHECK(mem.data.size() <= memory_max_bytes);
      }
      memory_count += 1;
    } else if (std::holds_alternative<w1::rewind::boundary_record>(record)) {
      const auto& boundary = std::get<w1::rewind::boundary_record>(record);
      CHECK(instruction_sequences.find(boundary.sequence) != instruction_sequences.end());
      boundary_count += 1;
    } else if (std::holds_alternative<w1::rewind::thread_start_record>(record)) {
      thread_start_count += 1;
    } else if (std::holds_alternative<w1::rewind::thread_end_record>(record)) {
      thread_end_count += 1;
    }
  }

  CHECK(reader.error().empty());
  CHECK(reader.header().version == w1::rewind::k_trace_version);
  CHECK((reader.header().flags & w1::rewind::trace_flag_instructions) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_blocks) == 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_register_deltas) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_memory_access) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_memory_values) != 0);
  CHECK((reader.header().flags & w1::rewind::trace_flag_boundaries) != 0);
  CHECK(!reader.register_table().empty());
  CHECK(!reader.module_table().empty());

  CHECK(instruction_count > 0);
  CHECK(delta_count > 0);
  CHECK(memory_count > 0);
  CHECK(boundary_count > 0);
  CHECK(thread_start_count == 1);
  CHECK(thread_end_count == 1);
  CHECK(delta_count <= instruction_count);
  CHECK(saw_truncated);
  CHECK(boundary_count == instruction_count / config.boundary_interval);

  fs::remove(path);
}
