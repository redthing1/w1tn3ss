#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/engine/tracer_config_base.hpp>

namespace w1trace {

struct trace_config : public w1::tracer_config_base {
  std::string output_file = "";
  size_t buffer_size = 256 * 1024 * 1024; // 256MB default
  int verbose = 0;

  static trace_config from_environment() {
    w1::util::env_config loader("W1TRACE_");

    trace_config config;
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    config.output_file = loader.get<std::string>("OUTPUT", "");
    config.buffer_size = static_cast<size_t>(loader.get<uint64_t>("BUFFER_SIZE", 256 * 1024 * 1024));
    config.verbose = loader.get<int>("VERBOSE", 0);

    return config;
  }
};

} // namespace w1trace