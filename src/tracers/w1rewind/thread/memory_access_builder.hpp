#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "config/rewind_config.hpp"
#include "w1base/types.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1instrument/tracer/types.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

struct pending_memory_access {
  w1::rewind::mem_access_op op = w1::rewind::mem_access_op::read;
  uint32_t space_id = 0;
  uint64_t address = 0;
  uint32_t size = 0;
  uint8_t flags = 0;
  std::vector<uint8_t> data;
};

void append_memory_access(
    const rewind_config& config, w1::trace_context& ctx, const w1::memory_event& event, w1::rewind::mem_access_op op,
    std::span<const w1::address_range> segments, std::vector<pending_memory_access>& out, uint64_t& memory_events,
    uint32_t space_id = 0
);

} // namespace w1rewind
