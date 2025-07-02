#pragma once

#include <string>
#include <vector>
#include <w1tn3ss/util/env_config.hpp>

namespace w1cov {

struct coverage_config {
  std::string output_file = "coverage.drcov";
  bool exclude_system_modules = true;
  std::vector<std::string> module_filter;
  bool track_hitcounts = true;

  static coverage_config from_environment() {
    w1::util::env_config loader("W1COV_");

    coverage_config config;
    config.output_file = loader.get<std::string>("OUTPUT_FILE", "coverage.drcov");
    config.exclude_system_modules = loader.get<bool>("EXCLUDE_SYSTEM", true);
    config.track_hitcounts = loader.get<bool>("TRACK_HITCOUNTS", true);
    auto module_filter_env = loader.get_list("MODULE_FILTER");
    if (!module_filter_env.empty()) {
      config.module_filter = module_filter_env;
    }

    return config;
  }
};

} // namespace w1cov