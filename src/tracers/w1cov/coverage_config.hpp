#pragma once

#include <string>
#include <vector>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/engine/instrumentation_config.hpp>

namespace w1cov {

struct coverage_config : public w1::instrumentation_config {
  int verbose = 0;
  std::string output_file = "coverage.drcov";
  bool inst_trace = false;

  static coverage_config from_environment() {
    w1::util::env_config loader("W1COV_");

    coverage_config config;
    config.verbose = loader.get<int>("VERBOSE", 0);
    config.output_file = loader.get<std::string>("OUTPUT", "coverage.drcov");
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    config.inst_trace = loader.get<bool>("INST_TRACE", false);
    auto module_filter_env = loader.get_list("MODULE_FILTER");
    if (!module_filter_env.empty()) {
      config.module_filter = module_filter_env;
    }

    return config;
  }
};

} // namespace w1cov