#pragma once

#include <string>
#include <w1tn3ss/util/env_config.hpp>

namespace w1xfer {

struct transfer_config {
  int verbose = 0;
  std::string output_file = "transfers.json";
  uint64_t max_entries = 1000000;
  bool log_registers = true;
  bool log_stack_info = true;
  bool log_call_targets = true;

  static transfer_config from_environment() {
    w1::util::env_config loader("W1XFER_");

    transfer_config config;
    config.verbose = loader.get<int>("VERBOSE", 0);
    config.output_file = loader.get<std::string>("OUTPUT", "transfers.json");
    config.max_entries = loader.get<uint64_t>("MAX_ENTRIES", 1000000);
    config.log_registers = loader.get<bool>("LOG_REGISTERS", true);
    config.log_stack_info = loader.get<bool>("LOG_STACK_INFO", true);
    config.log_call_targets = loader.get<bool>("LOG_CALL_TARGETS", true);

    return config;
  }
};

} // namespace w1xfer