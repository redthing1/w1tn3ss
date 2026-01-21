#pragma once

#include <cstdint>
#include <optional>

#include "gdbstub/target/target.hpp"

namespace w1replay::gdb {

struct thread_state {
  uint64_t active_thread_id = 0;
  std::optional<gdbstub::stop_reason> last_stop;
};

} // namespace w1replay::gdb
