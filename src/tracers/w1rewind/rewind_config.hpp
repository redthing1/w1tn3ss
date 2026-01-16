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

  bool record_instructions = false;
  bool record_register_deltas = false;
  uint64_t boundary_interval = 4096;
  uint64_t stack_window_bytes = 0;

  struct memory_capture_options {
    bool enabled = false;
    bool include_reads = false;
    bool include_values = false;
    uint32_t max_value_bytes = 32;
  };

  memory_capture_options memory{};
  std::string output_path;

  static rewind_config from_environment();
  bool requires_instruction_flow() const;
};

} // namespace w1rewind
