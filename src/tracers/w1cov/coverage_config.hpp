#pragma once

#include <string>
#include <vector>

#include "w1tn3ss/core/instrumentation_policy.hpp"
#include "w1tn3ss/util/env_config.hpp"

namespace w1cov {

struct coverage_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  int verbose = 0;
  std::string output_file = "coverage.drcov";
  bool inst_trace = false;

  static coverage_config from_environment() {
    w1::util::env_config loader("W1COV");

    coverage_config config;
    using system_policy = w1::core::system_module_policy;
    system_policy policy = system_policy::exclude_all;
    policy = loader.get_enum<system_policy>(
        {
            {"exclude", system_policy::exclude_all},
            {"exclude_all", system_policy::exclude_all},
            {"none", system_policy::exclude_all},
            {"critical", system_policy::include_critical},
            {"include_critical", system_policy::include_critical},
            {"all", system_policy::include_all},
            {"include_all", system_policy::include_all},
            {"include", system_policy::include_all},
        },
        "SYSTEM_POLICY",
        policy
    );
    config.instrumentation.system_policy = policy;
    config.instrumentation.include_unnamed_modules = loader.get<bool>("INCLUDE_UNNAMED", false);
    config.instrumentation.use_default_excludes = loader.get<bool>("USE_DEFAULT_EXCLUDES", true);
    config.instrumentation.include_modules = loader.get_list("INCLUDE");
    config.instrumentation.exclude_modules = loader.get_list("EXCLUDE");
    config.exclude_self = loader.get<bool>("EXCLUDE_SELF", true);

    config.verbose = loader.get<int>("VERBOSE", 0);
    config.output_file = loader.get<std::string>("OUTPUT", "coverage.drcov");
    config.inst_trace = loader.get<bool>("INST_TRACE", false);
    auto module_filter_env = loader.get_list("MODULE_FILTER");
    if (!module_filter_env.empty()) {
      config.instrumentation.include_modules.insert(
          config.instrumentation.include_modules.end(), module_filter_env.begin(), module_filter_env.end()
      );
    }

    return config;
  }
};

} // namespace w1cov
