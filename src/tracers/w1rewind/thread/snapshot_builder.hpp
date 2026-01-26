#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "engine/register_schema.hpp"
#include "config/rewind_config.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1runtime/register_capture.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

struct pending_snapshot {
  uint64_t snapshot_id = 0;
  std::vector<w1::rewind::reg_write_entry> registers;
  std::vector<w1::rewind::memory_segment> memory_segments;
  std::string reason;
};

struct snapshot_state {
  uint64_t snapshot_count = 0;
  uint64_t flow_since_register_snapshot = 0;
  uint64_t flow_since_stack_snapshot = 0;
  bool warned_missing_frame = false;
};

std::optional<pending_snapshot> maybe_capture_snapshot(
    w1::trace_context& ctx, const w1::util::register_state& regs, const register_schema& schema,
    const rewind_config& config, snapshot_state& state, redlog::logger log, w1::rewind::endian byte_order
);

} // namespace w1rewind
