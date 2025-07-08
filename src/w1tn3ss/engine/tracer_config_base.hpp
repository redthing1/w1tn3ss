#pragma once

#include <string>
#include <vector>

namespace w1 {

/**
 * @brief base configuration for all tracers
 * @details provides common options that apply to most tracing scenarios
 */
struct tracer_config_base {
  // include system libraries in instrumentation
  bool include_system_modules = false;

  // optional module name filters for targeted instrumentation
  std::vector<std::string> module_filter;
};

} // namespace w1