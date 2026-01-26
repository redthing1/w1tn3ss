#pragma once

#include <optional>
#include <vector>

#include "engine/register_schema.hpp"
#include "w1runtime/register_capture.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

std::vector<w1::rewind::reg_write_entry> capture_register_deltas(
    const register_schema& schema, const w1::util::register_state& regs, w1::rewind::endian byte_order,
    std::optional<w1::util::register_state>& last_regs
);

std::vector<w1::rewind::reg_write_entry> capture_register_snapshot(
    const register_schema& schema, const w1::util::register_state& regs, w1::rewind::endian byte_order
);

} // namespace w1rewind
