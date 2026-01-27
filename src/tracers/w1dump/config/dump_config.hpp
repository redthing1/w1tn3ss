#pragma once

#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "w1instrument/config/tracer_common_config.hpp"
#include "w1base/env_config.hpp"

namespace w1dump {

enum class dump_trigger_mode { entry, instruction, address, module_offset };

struct dump_config {
  w1::instrument::config::tracer_common_config common{};
  std::string output = "process.w1dump";
  bool dump_memory_content = false;
  std::vector<std::string> filters;
  uint64_t max_region_size = 100 * 1024 * 1024;

  dump_trigger_mode trigger = dump_trigger_mode::entry;
  std::optional<uint64_t> trigger_address;
  std::string trigger_module;
  std::optional<uint64_t> trigger_offset;

  static dump_config from_environment() {
    w1::util::env_config loader("W1DUMP");

    dump_config config;
    config.common = w1::instrument::config::load_common(loader);
    config.output = loader.get<std::string>("OUTPUT", "process.w1dump");
    config.dump_memory_content = loader.get<bool>("DUMP_MEMORY_CONTENT", false);

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

    const std::string trigger_str = loader.get<std::string>("TRIGGER", "entry");
    config.trigger = parse_trigger_mode(trigger_str);

    if (const std::string address_str = loader.get<std::string>("TRIGGER_ADDRESS", ""); !address_str.empty()) {
      config.trigger_address = parse_u64(address_str);
    }
    config.trigger_module = loader.get<std::string>("TRIGGER_MODULE", "");
    if (const std::string offset_str = loader.get<std::string>("TRIGGER_OFFSET", ""); !offset_str.empty()) {
      config.trigger_offset = parse_u64(offset_str);
    }

    return config;
  }

  static dump_trigger_mode parse_trigger_mode(std::string_view value) {
    if (value == "entry") {
      return dump_trigger_mode::entry;
    }
    if (value == "instruction") {
      return dump_trigger_mode::instruction;
    }
    if (value == "address") {
      return dump_trigger_mode::address;
    }
    if (value == "module-offset" || value == "module_offset") {
      return dump_trigger_mode::module_offset;
    }
    return dump_trigger_mode::entry;
  }

  static const char* trigger_name(dump_trigger_mode mode) {
    switch (mode) {
    case dump_trigger_mode::entry:
      return "entry";
    case dump_trigger_mode::instruction:
      return "instruction";
    case dump_trigger_mode::address:
      return "address";
    case dump_trigger_mode::module_offset:
      return "module-offset";
    }
    return "entry";
  }

  static std::optional<uint64_t> parse_u64(std::string_view value) {
    if (value.empty()) {
      return std::nullopt;
    }
    size_t pos = 0;
    uint64_t parsed = 0;
    try {
      parsed = std::stoull(std::string(value), &pos, 0);
    } catch (...) {
      return std::nullopt;
    }
    if (pos == 0) {
      return std::nullopt;
    }
    return parsed;
  }
};

} // namespace w1dump
