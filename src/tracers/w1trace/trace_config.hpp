#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>

namespace w1trace {

struct trace_config {
  std::string output_file = "trace.txt";
  size_t buffer_size = 256 * 1024 * 1024; // 256MB default
  bool verbose = false;

  static trace_config from_environment() {
    w1::util::env_config loader("W1TRACE_");

    trace_config config;
    config.output_file = loader.get<std::string>("OUTPUT_FILE", "trace.txt");
    config.buffer_size = static_cast<size_t>(loader.get<uint64_t>("BUFFER_SIZE", 256 * 1024 * 1024));
    config.verbose = loader.get<bool>("VERBOSE", false);

    return config;
  }
};

} // namespace w1trace