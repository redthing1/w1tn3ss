#pragma once

#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

#include "w1tn3ss/core/instrumentation_policy.hpp"
#include "w1tn3ss/util/env_config.hpp"

namespace w1dump {

struct dump_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  std::string output = "process.w1dump";
  bool dump_memory_content = false;
  std::vector<std::string> filters;
  uint64_t max_region_size = 100 * 1024 * 1024;
  bool dump_on_entry = true;
  int verbose = 0;

  static dump_config from_environment() {
    w1::util::env_config loader("W1DUMP");

    dump_config config;
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

    config.output = loader.get<std::string>("OUTPUT", "process.w1dump");
    config.dump_memory_content = loader.get<bool>("DUMP_MEMORY_CONTENT", false);
    config.dump_on_entry = loader.get<bool>("DUMP_ON_ENTRY", true);
    config.verbose = loader.get<int>("VERBOSE", 0);

    config.filters = loader.get_list("FILTERS");
    int filter_count = loader.get<int>("FILTER_COUNT", 0);
    for (int i = 0; i < filter_count; ++i) {
      std::string key = "FILTER_" + std::to_string(i);
      std::string filter = loader.get<std::string>(key, "");
      if (!filter.empty()) {
        config.filters.push_back(filter);
      }
    }

    std::string max_size_str = loader.get<std::string>("MAX_REGION_SIZE", "");
    if (!max_size_str.empty()) {
      uint64_t value = 0;
      char unit = 0;
      size_t pos = 0;
      value = std::stoull(max_size_str, &pos);
      if (pos < max_size_str.size()) {
        unit = static_cast<char>(std::toupper(max_size_str[pos]));
      }

      switch (unit) {
      case 'K':
        value *= 1024;
        break;
      case 'M':
        value *= 1024 * 1024;
        break;
      case 'G':
        value *= 1024 * 1024 * 1024;
        break;
      default:
        break;
      }

      if (value > 0) {
        config.max_region_size = value;
      }
    }

    return config;
  }
};

} // namespace w1dump
