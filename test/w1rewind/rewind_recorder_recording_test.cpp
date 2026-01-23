#include <filesystem>
#include <unordered_set>
#include <vector>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/runtime/rewind_runtime.hpp"
#include "w1rewind/trace/trace_reader.hpp"

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

TEST_CASE("w1rewind records instruction flow, memory, and snapshots") {
  namespace fs = std::filesystem;

  fs::path path = fs::temp_directory_path() / "w1rewind_recorder_recording.trace";

  w1rewind::rewind_config config;
  config.output_path = path.string();
  config.flow.mode = w1rewind::rewind_config::flow_options::flow_mode::instruction;
  config.registers.deltas = true;
  config.registers.snapshot_interval = 8;
  config.stack_window.mode = w1rewind::rewind_config::stack_window_options::window_mode::none;
  config.stack_snapshots.interval = 0;
  config.memory.access = w1rewind::rewind_config::memory_access::reads_writes;
  config.memory.values = true;
  config.memory.max_value_bytes = 4;
  config.common.instrumentation.include_modules = {"w1rewind_unit_tests"};

  auto runtime = w1rewind::make_thread_runtime(config);
  std::vector<uint64_t> args;
  args.push_back(64);
  uint64_t result = 0;
  bool ok = w1rewind::with_runtime(runtime, [&](auto& active) {
    return active.call(reinterpret_cast<uint64_t>(&rewind_test_worker), args, &result, "unit_main");
  });
  if (!ok) {
    WARN("thread runtime could not instrument modules; module scanning may be blocked");
    return;
  }
  REQUIRE(w1rewind::with_runtime(runtime, [](auto& active) { return active.export_output(); }));

  w1::rewind::trace_reader reader(path.string());
  REQUIRE(reader.open());

  size_t instruction_count = 0;
  size_t delta_count = 0;
  size_t memory_count = 0;
  size_t snapshot_count = 0;
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
    } else if (std::holds_alternative<w1::rewind::snapshot_record>(record)) {
      const auto& snapshot = std::get<w1::rewind::snapshot_record>(record);
      CHECK(instruction_sequences.find(snapshot.sequence) != instruction_sequences.end());
      snapshot_count += 1;
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
  CHECK((reader.header().flags & w1::rewind::trace_flag_snapshots) != 0);
  CHECK(reader.target_info().has_value());
  CHECK(reader.target_environment().has_value());
  CHECK(!reader.register_specs().empty());
  CHECK(!reader.module_table().empty());
  CHECK(!reader.memory_map().empty());

  CHECK(instruction_count > 0);
  CHECK(delta_count > 0);
  CHECK(memory_count > 0);
  CHECK(snapshot_count > 0);
  CHECK(thread_start_count == 1);
  CHECK(thread_end_count == 1);
  CHECK(delta_count <= instruction_count);
  CHECK(saw_truncated);
  CHECK(snapshot_count == instruction_count / config.registers.snapshot_interval);

  reader.close();
  fs::remove(path);
}
