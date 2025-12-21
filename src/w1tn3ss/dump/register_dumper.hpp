#pragma once

#include "w1tn3ss/dump/dump_format.hpp"

#include <QBDI.h>
#include <redlog.hpp>

#include <cstdint>

namespace w1::dump {

class register_dumper {
public:
  static thread_state capture_thread_state(
      const QBDI::GPRState& gpr, const QBDI::FPRState& fpr, uint64_t thread_id
  );

private:
  static redlog::logger log_;
};

} // namespace w1::dump
