#pragma once

#include "trace_tracer.hpp"
#include "trace_config.hpp"
#include <w1tn3ss/engine/session_base.hpp>

namespace w1trace {

class session : public w1::session_base<session, trace_tracer, trace_config> {
public:
  session() = default;
  explicit session(const trace_config& config) : session_base(config) {}

  // trace-specific metrics
  size_t get_instruction_count() const { return get_tracer()->get_instruction_count(); }
  size_t get_flush_count() const { return get_tracer()->get_flush_count(); }
  size_t get_buffer_usage() const { return get_tracer()->get_buffer_usage(); }
};

} // namespace w1trace