#pragma once

#include <QBDI.h>
#include <redlog.hpp>
#include "dump_format.hpp"

namespace w1 {
namespace dump {

class register_dumper {
public:
  // capture current thread state from qbdi
  static thread_state capture_thread_state(const QBDI::GPRState& gpr, const QBDI::FPRState& fpr);

private:
  static redlog::logger log_;
};

} // namespace dump
} // namespace w1