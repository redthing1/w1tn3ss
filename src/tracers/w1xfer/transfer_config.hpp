#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/engine/instrumentation_config.hpp>

namespace w1xfer {

struct transfer_config : public w1::instrumentation_config {
  int verbose = 0;
  std::string output_file = "";
  bool log_registers = true;
  bool log_stack_info = true;
  bool log_call_targets = true;
  bool analyze_apis = false;

  static transfer_config from_environment() {
    w1::util::env_config loader("W1XFER_");

    transfer_config config;
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    config.verbose = loader.get<int>("VERBOSE", 0);
    config.output_file = loader.get<std::string>("OUTPUT", "");
    config.log_registers = loader.get<bool>("LOG_REGISTERS", true);
    config.log_stack_info = loader.get<bool>("LOG_STACK_INFO", true);
    config.log_call_targets = loader.get<bool>("LOG_CALL_TARGETS", true);
    config.analyze_apis = loader.get<bool>("ANALYZE_APIS", false);

    return config;
  }
};

} // namespace w1xfer