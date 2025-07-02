#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>

namespace w1mem {

struct memory_config {
  std::string output_path;
  uint64_t max_trace_entries;
  bool collect_trace;
  bool verbose;

  static memory_config from_environment() {
    w1::util::env_config loader("W1MEM_");

    memory_config config;
    config.output_path = loader.get<std::string>("OUTPUT", "w1mem_trace.json");
    config.max_trace_entries = loader.get<uint64_t>("MAX_TRACE", 100000);
    config.collect_trace = !loader.get<bool>("STATS_ONLY", false);
    config.verbose = loader.get<bool>("VERBOSE", false);

    return config;
  }
};

} // namespace w1mem