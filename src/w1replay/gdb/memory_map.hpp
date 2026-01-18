#pragma once

#include <vector>

#include "gdbstub/target.hpp"

#include "w1tn3ss/runtime/rewind/replay_state.hpp"
#include "w1tn3ss/runtime/rewind/trace_format.hpp"

namespace w1replay::gdb {

std::vector<gdbstub::memory_region> build_memory_map(
    const std::vector<w1::rewind::module_record>& modules,
    const w1::rewind::replay_state* state
);

} // namespace w1replay::gdb
