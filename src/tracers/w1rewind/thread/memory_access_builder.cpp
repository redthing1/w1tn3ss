#include "memory_access_builder.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include "w1runtime/memory_reader.hpp"

namespace w1rewind {

void append_memory_access(
    const rewind_config& config, w1::trace_context& ctx, const w1::memory_event& event, w1::rewind::mem_access_op op,
    std::span<const w1::address_range> segments, std::vector<pending_memory_access>& out, uint64_t& memory_events,
    uint32_t space_id
) {
  if (segments.empty()) {
    return;
  }

  bool capture_values = config.memory.values && config.memory.max_value_bytes > 0;
  uint32_t max_bytes = config.memory.max_value_bytes;
  std::array<uint8_t, 8> value_bytes{};
  bool have_value_bytes = false;

  if (capture_values && event.value_valid) {
    uint64_t value = event.value;
    for (size_t i = 0; i < value_bytes.size(); ++i) {
      value_bytes[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
    have_value_bytes = true;
  }

  for (const auto& segment : segments) {
    if (segment.end <= segment.start) {
      continue;
    }
    uint64_t seg_size_u64 = segment.end - segment.start;
    if (seg_size_u64 > std::numeric_limits<uint32_t>::max()) {
      continue;
    }
    uint32_t seg_size = static_cast<uint32_t>(seg_size_u64);

    pending_memory_access record{};
    record.op = op;
    record.space_id = space_id;
    record.address = segment.start;
    record.size = seg_size;
    bool value_known = false;
    bool value_truncated = false;

    if (capture_values && seg_size > 0) {
      uint32_t capture_size = std::min(seg_size, max_bytes);
      if (capture_size > 0) {
        if (segment.start < event.address) {
          continue;
        }
        uint64_t offset = segment.start - event.address;
        if (have_value_bytes && (offset + capture_size) <= value_bytes.size()) {
          record.data.assign(
              value_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              value_bytes.begin() + static_cast<std::ptrdiff_t>(offset + capture_size)
          );
          value_known = true;
        } else {
          auto bytes = ctx.memory().read_bytes(segment.start, capture_size);
          if (bytes.has_value()) {
            record.data = std::move(*bytes);
            value_known = true;
          }
        }
        value_truncated = seg_size > capture_size;
      }
    }

    if (value_known) {
      record.flags |= w1::rewind::mem_access_value_known;
    }
    if (value_truncated) {
      record.flags |= w1::rewind::mem_access_value_truncated;
    }

    out.push_back(std::move(record));
    memory_events += 1;
  }
}

} // namespace w1rewind
