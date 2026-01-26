#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "w1replay/modules/image_layout_provider.hpp"

namespace w1replay::commands {

struct inspect_options {
  std::string trace_path;
  std::string index_path;
  uint32_t index_stride = 0;
  uint64_t thread_id = 0;
  uint64_t start_sequence = 0;
  uint32_t count = 10;
  uint32_t history_size = 1024;
  bool reverse = false;
  bool instruction_steps = false;
  bool show_registers = false;
  std::string memory_range;
  std::string memory_space;
  std::string checkpoint_path;
  std::vector<std::string> image_mappings;
  std::vector<std::string> image_dirs;
  w1replay::image_layout_mode image_layout = w1replay::image_layout_mode::trace;
  bool json_output = false;
};

int inspect(const inspect_options& options);

} // namespace w1replay::commands
