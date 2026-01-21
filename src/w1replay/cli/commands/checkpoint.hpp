#pragma once

#include <cstdint>
#include <string>

namespace w1replay::commands {

struct checkpoint_options {
  std::string trace_path;
  std::string output_path;
  uint32_t stride = 50000;
  bool include_memory = false;
  uint64_t thread_id = 0;
};

int checkpoint(const checkpoint_options& options);

} // namespace w1replay::commands
