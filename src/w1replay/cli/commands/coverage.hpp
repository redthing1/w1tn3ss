#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace w1replay::commands {

struct coverage_options {
  std::string trace_path;
  std::string output_path;
  std::string flow = "auto";
  uint64_t thread_id = 0;
  std::string space;
  bool include_unknown = false;
  std::vector<std::string> image_mappings;
  std::vector<std::string> image_dirs;
};

int coverage(const coverage_options& options);

} // namespace w1replay::commands
