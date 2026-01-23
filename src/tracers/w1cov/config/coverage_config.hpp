#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "w1base/env_config.hpp"
#include "w1instrument/config/tracer_common_config.hpp"

namespace w1cov {

enum class coverage_mode : uint8_t {
  basic_block,
  instruction,
};

inline constexpr const char* coverage_mode_name(coverage_mode mode) {
  switch (mode) {
    case coverage_mode::instruction:
      return "instruction";
    case coverage_mode::basic_block:
    default:
      return "basic_block";
  }
}

struct coverage_config {
  w1::instrument::config::tracer_common_config common{};
  w1::instrument::config::thread_attach_policy threads =
      w1::instrument::config::thread_attach_policy::auto_attach;
  std::string output_file = "coverage.drcov";
  coverage_mode mode = coverage_mode::basic_block;
  uint64_t buffer_flush_threshold = 0;

  static coverage_config from_environment() {
    w1::util::env_config loader("W1COV");

    coverage_config config;
    config.common = w1::instrument::config::load_common(loader);
    config.threads = w1::instrument::config::load_thread_attach_policy(
        loader, w1::instrument::config::thread_attach_policy::auto_attach
    );
    config.output_file = loader.get<std::string>("OUTPUT", "coverage.drcov");
    config.buffer_flush_threshold = loader.get<uint64_t>("BUFFER_FLUSH_THRESHOLD", 0);

    const std::string mode = loader.get<std::string>("MODE", "basic_block");
    if (mode == "instruction" || mode == "inst" || mode == "instruction_trace") {
      config.mode = coverage_mode::instruction;
    } else {
      config.mode = coverage_mode::basic_block;
    }

    auto module_filter_env = loader.get_list("MODULE_FILTER");
    if (!module_filter_env.empty()) {
      config.common.instrumentation.include_modules.insert(
          config.common.instrumentation.include_modules.end(), module_filter_env.begin(), module_filter_env.end()
      );
    }

    return config;
  }
};

} // namespace w1cov
