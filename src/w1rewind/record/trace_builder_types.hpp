#pragma once

#include <memory>

#include <redlog.hpp>

#include "w1rewind/trace/record_sink.hpp"

namespace w1::rewind {

struct trace_builder_config {
  std::shared_ptr<trace_record_sink> sink;
  redlog::logger log;
};

} // namespace w1::rewind
