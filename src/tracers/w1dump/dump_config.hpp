#pragma once

#include <string>
#include <w1tn3ss/engine/instrumentation_config.hpp>

namespace w1dump {

struct dump_config : public w1::instrumentation_config {
  std::string output = "process.w1dump";
  bool dump_memory_content = false;
  std::vector<std::string> filters;             // filter strings to parse
  uint64_t max_region_size = 100 * 1024 * 1024; // 100mb default
  bool dump_on_entry = true;
};

} // namespace w1dump