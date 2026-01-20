#pragma once

#include <vector>

#include "gdbstub/target/target.hpp"

#include "w1rewind/replay/replay_state.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1replay::gdb {

std::vector<gdbstub::memory_region> build_memory_map(
    const std::vector<w1::rewind::module_record>& modules,
    const std::vector<w1::rewind::memory_region_record>& memory_map, const w1::rewind::replay_state* state
);

} // namespace w1replay::gdb
