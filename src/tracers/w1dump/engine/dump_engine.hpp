#pragma once

#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

#include "config/dump_config.hpp"
#include "w1dump/memory_dumper.hpp"
#include "w1instrument/tracer/trace_context.hpp"

namespace w1dump {

class dump_engine {
public:
  explicit dump_engine(dump_config config);

  const dump_config& config() const { return config_; }
  bool dump_completed() const { return dumped_; }

  bool dump_once(w1::trace_context& ctx, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

private:
  std::vector<w1::dump::dump_options::filter> parse_filters() const;

  dump_config config_{};
  w1::dump::dump_options options_{};
  redlog::logger log_ = redlog::get_logger("w1dump.engine");
  bool dumped_ = false;
};

} // namespace w1dump
