#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "w1replay/modules/image_layout_provider.hpp"

namespace w1replay::commands {

struct server_options {
  std::string trace_path;
  std::string index_path;
  uint32_t index_stride = 0;
  std::string checkpoint_path;
  std::string gdb_listen;
  uint64_t thread_id = 0;
  uint64_t start_sequence = 0;
  bool instruction_steps = false;
  std::vector<std::string> image_mappings;
  std::vector<std::string> image_dirs;
  w1replay::image_layout_mode image_layout = w1replay::image_layout_mode::trace;
};

int server(const server_options& options);

} // namespace w1replay::commands
