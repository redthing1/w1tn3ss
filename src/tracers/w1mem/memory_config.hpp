#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/engine/instrumentation_config.hpp>

namespace w1mem {

struct memory_config : public w1::instrumentation_config {
  int verbose = 0;
  std::string output_path;

  static memory_config from_environment() {
    w1::util::env_config loader("W1MEM_");

    memory_config config;
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    config.verbose = loader.get<int>("VERBOSE", 0);
    config.output_path = loader.get<std::string>("OUTPUT", "");

    return config;
  }
};

} // namespace w1mem