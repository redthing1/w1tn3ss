#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace w1replay::commands {

struct inspect_options {
  std::string trace_path;
  std::string index_path;
  uint64_t thread_id = 0;
  uint64_t start_sequence = 0;
  uint32_t count = 10;
  uint32_t history_size = 1024;
  bool reverse = false;
  bool instruction_steps = false;
  bool show_registers = false;
  std::string memory_range;
  std::string checkpoint_path;
  std::vector<std::string> module_mappings;
  std::vector<std::string> module_dirs;
};

int inspect(const inspect_options& options);

} // namespace w1replay::commands
