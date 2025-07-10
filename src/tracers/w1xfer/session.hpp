#pragma once

#include "transfer_tracer.hpp"
#include "transfer_config.hpp"
#include <w1tn3ss/engine/session_base.hpp>

namespace w1xfer {

class session : public w1::session_base<session, transfer_tracer, transfer_config> {
public:
  session() = default;
  explicit session(const transfer_config& config) : session_base(config) {}

  // transfer-specific metrics
  const transfer_stats& get_stats() const { return get_tracer()->get_stats(); }
};

} // namespace w1xfer