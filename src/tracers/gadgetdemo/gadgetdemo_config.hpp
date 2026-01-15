#pragma once

#include <cstdint>

#include "w1tn3ss/core/instrumentation_policy.hpp"
#include "w1tn3ss/util/env_config.hpp"

namespace gadgetdemo {

struct gadgetdemo_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  int verbose = 0;
  uint64_t trigger_count = 100;
  bool run_immediate = true;
  bool debug_gadgets = false;

  static gadgetdemo_config from_environment() {
    w1::util::env_config loader("GADGETDEMO");

    gadgetdemo_config config;
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
        "SYSTEM_POLICY", policy
    );
    config.instrumentation.system_policy = policy;
    config.instrumentation.include_unnamed_modules = loader.get<bool>("INCLUDE_UNNAMED", false);
    config.instrumentation.use_default_excludes = loader.get<bool>("USE_DEFAULT_EXCLUDES", true);
    config.instrumentation.include_modules = loader.get_list("INCLUDE");
    config.instrumentation.exclude_modules = loader.get_list("EXCLUDE");
    config.exclude_self = loader.get<bool>("EXCLUDE_SELF", true);

    config.verbose = loader.get<int>("VERBOSE", 0);
    config.trigger_count = loader.get<uint64_t>("TRIGGER_COUNT", 100);
    config.run_immediate = loader.get<bool>("RUN_IMMEDIATE", true);
    config.debug_gadgets = loader.get<bool>("DEBUG_GADGETS", false);

    return config;
  }
};

} // namespace gadgetdemo
