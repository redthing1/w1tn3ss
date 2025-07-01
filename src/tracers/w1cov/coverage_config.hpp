#pragma once

#include <string>
#include <vector>

namespace w1cov {

struct coverage_config {
  std::string output_file = "coverage.drcov";
  bool exclude_system_modules = true;
  std::vector<std::string> module_filter;
  bool track_hitcounts = true;
};

} // namespace w1cov