#pragma once

#include <cstddef>
#include <string>

#include "w1instrument/core/instrumentation_policy.hpp"
#include "w1base/env_config.hpp"

namespace w1trace {

struct trace_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  std::string output_file = "";
  size_t buffer_size_bytes = 256 * 1024 * 1024;
  size_t flush_event_count = 1'000'000;
  size_t flush_byte_count = 0;
  bool track_control_flow = false;
  int verbose = 0;

  static trace_config from_environment() {
    w1::util::env_config loader("W1TRACE");

    trace_config config;
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

    config.output_file = loader.get<std::string>("OUTPUT", "");
    config.buffer_size_bytes = static_cast<size_t>(loader.get<uint64_t>("BUFFER_SIZE", 256 * 1024 * 1024));
    config.flush_event_count = static_cast<size_t>(loader.get<uint64_t>("FLUSH_EVENTS", 1'000'000));
    config.flush_byte_count = static_cast<size_t>(loader.get<uint64_t>("FLUSH_BYTES", 0));
    config.track_control_flow = loader.get<bool>("TRACK_CONTROL_FLOW", false);
    config.verbose = loader.get<int>("VERBOSE", 0);

    return config;
  }
};

} // namespace w1trace
