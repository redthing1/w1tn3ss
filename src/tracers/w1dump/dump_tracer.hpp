#pragma once

#include <QBDI.h>
#include <redlog.hpp>
#include <string>
#include <w1tn3ss/dump/memory_dumper.hpp>
#include "dump_config.hpp"

namespace w1dump {

class dump_tracer {
public:
  explicit dump_tracer(const dump_config& config);

  // called when vm starts
  void on_vm_start(QBDI::VMInstanceRef vm);

  // name for registration
  std::string get_name() const { return "w1dump"; }

private:
  dump_config config_;
  redlog::logger log_ = redlog::get_logger("w1dump.tracer");
  bool dumped_ = false; // ensure we only dump once

  void perform_dump(QBDI::VMInstanceRef vm);
  std::vector<w1::dump::dump_options::filter> parse_filters() const;
};

} // namespace w1dump