#pragma once

#include <vector>

#include "gdbstub/target/target.hpp"

#include "w1rewind/replay/replay_state.hpp"
#include "w1rewind/replay/mapping_state.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1replay {
class image_path_resolver;
}

namespace w1::rewind {
struct replay_context;
class mapping_state;
} // namespace w1::rewind

namespace w1replay::gdb {

std::vector<gdbstub::memory_region> build_memory_map(
    const w1::rewind::replay_context& context, const w1::rewind::replay_state* state,
    const w1::rewind::mapping_state* mappings, const image_path_resolver* resolver
);

} // namespace w1replay::gdb
