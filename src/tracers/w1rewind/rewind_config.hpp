#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "w1tn3ss/core/instrumentation_policy.hpp"

namespace w1rewind {

struct rewind_config {
  w1::core::instrumentation_policy instrumentation{};
  bool exclude_self = true;
  int verbose = 0;
  bool record_instructions = true;
  bool record_registers = true;
  bool record_memory = true;
  bool capture_memory_reads = false;
  uint64_t frame_instruction_interval = 0;
  std::string output_path;
  std::string compare_trace_path;

  enum class validation_mode { none, log_only, strict };
  validation_mode mode = validation_mode::none;
  uint64_t max_mismatches = 1;
  uint64_t stack_window_bytes = 0x4000;
  std::vector<std::string> ignore_registers;
  std::vector<std::string> ignore_modules;

  static rewind_config from_environment();
};

} // namespace w1rewind
