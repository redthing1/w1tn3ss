#pragma once

#include <optional>
#include <vector>

#include "register_schema.hpp"
#include "w1runtime/register_capture.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

std::vector<w1::rewind::register_delta> capture_register_deltas(
    const register_schema& schema, const w1::util::register_state& regs,
    std::optional<w1::util::register_state>& last_regs
);

std::vector<w1::rewind::register_delta> capture_register_snapshot(
    const register_schema& schema, const w1::util::register_state& regs
);

} // namespace w1rewind
