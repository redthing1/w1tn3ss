#pragma once

#include <memory>

#include <redlog.hpp>

#include "w1rewind/record/trace_writer.hpp"

namespace w1::rewind {

struct trace_builder_options {
  bool record_instructions = false;
  bool record_register_deltas = false;
  bool record_memory_access = false;
  bool record_memory_values = false;
  bool record_snapshots = false;
  bool record_stack_snapshot = false;
};

struct trace_builder_config {
  std::shared_ptr<trace_writer> writer;
  redlog::logger log;
  trace_builder_options options;
};

} // namespace w1::rewind
