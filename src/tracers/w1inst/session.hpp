#pragma once

#include "instruction_tracer.hpp"
#include "instruction_config.hpp"
#include <w1tn3ss/engine/session_base.hpp>

namespace w1inst {

class session : public w1::session_base<session, instruction_tracer, instruction_config> {
public:
  session() = default;
  explicit session(const instruction_config& config) : session_base(config) {}

  // instruction-specific metrics
  const mnemonic_stats& get_stats() const { return get_tracer()->get_stats(); }
};

} // namespace w1inst