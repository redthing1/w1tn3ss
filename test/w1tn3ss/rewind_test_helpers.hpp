#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "w1tn3ss/runtime/rewind/trace_format.hpp"
#include "w1tn3ss/runtime/rewind/trace_writer.hpp"

namespace w1::rewind::test_helpers {

inline std::filesystem::path temp_path(const char* name) {
  return std::filesystem::temp_directory_path() / name;
}

inline void write_module_table(
    trace_writer& writer,
    uint64_t module_id,
    uint64_t base,
    const std::string& path = "test_module"
) {
  module_record module{};
  module.id = module_id;
  module.base = base;
  module.size = 0x1000;
  module.permissions = 5;
  module.path = path;

  module_table_record table{};
  table.modules.push_back(module);
  REQUIRE(writer.write_module_table(table));
}

inline void write_thread_start(trace_writer& writer, uint64_t thread_id, const std::string& name) {
  thread_start_record start{};
  start.thread_id = thread_id;
  start.name = name;
  REQUIRE(writer.write_thread_start(start));
}

inline void write_thread_end(trace_writer& writer, uint64_t thread_id) {
  thread_end_record end{};
  end.thread_id = thread_id;
  REQUIRE(writer.write_thread_end(end));
}

inline void write_block_def(
    trace_writer& writer,
    uint64_t block_id,
    uint64_t module_id,
    uint64_t module_offset,
    uint32_t size
) {
  block_definition_record record{};
  record.block_id = block_id;
  record.module_id = module_id;
  record.module_offset = module_offset;
  record.size = size;
  REQUIRE(writer.write_block_definition(record));
}

inline void write_block_exec(trace_writer& writer, uint64_t thread_id, uint64_t sequence, uint64_t block_id) {
  block_exec_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.block_id = block_id;
  REQUIRE(writer.write_block_exec(record));
}

inline void write_instruction(
    trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint64_t module_id,
    uint64_t module_offset
) {
  instruction_record record{};
  record.sequence = sequence;
  record.thread_id = thread_id;
  record.module_id = module_id;
  record.module_offset = module_offset;
  record.size = 4;
  record.flags = 0;
  REQUIRE(writer.write_instruction(record));
}

inline void write_register_table(trace_writer& writer, std::vector<std::string> names) {
  register_table_record reg_table{};
  reg_table.names = std::move(names);
  REQUIRE(writer.write_register_table(reg_table));
}

inline void write_register_delta(
    trace_writer& writer,
    uint64_t thread_id,
    uint64_t sequence,
    uint16_t reg_id,
    uint64_t value
) {
  register_delta_record deltas{};
  deltas.sequence = sequence;
  deltas.thread_id = thread_id;
  deltas.deltas = {register_delta{reg_id, value}};
  REQUIRE(writer.write_register_deltas(deltas));
}

} // namespace w1::rewind::test_helpers
