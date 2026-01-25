#pragma once

#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

#include "w1instrument/config/tracer_common_config.hpp"
#include "w1base/env_config.hpp"

namespace w1dump {

struct dump_config {
  w1::instrument::config::tracer_common_config common{};
  std::string output = "process.w1dump";
  bool dump_memory_content = false;
  std::vector<std::string> filters;
  uint64_t max_region_size = 100 * 1024 * 1024;
  bool dump_on_entry = true;

  static dump_config from_environment() {
    w1::util::env_config loader("W1DUMP");

    dump_config config;
    config.common = w1::instrument::config::load_common(loader);
    config.output = loader.get<std::string>("OUTPUT", "process.w1dump");
    config.dump_memory_content = loader.get<bool>("DUMP_MEMORY_CONTENT", false);
    config.dump_on_entry = loader.get<bool>("DUMP_ON_ENTRY", true);

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
