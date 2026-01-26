#include "stack_window_policy.hpp"

#include <algorithm>
#include <limits>
#include <optional>

namespace w1rewind {
namespace {

struct sp_window {
  uint64_t base = 0;
  uint64_t size = 0;
  uint64_t below = 0;
  uint64_t above = 0;
};

sp_window compute_sp_window(uint64_t sp, uint64_t above, uint64_t below) {
  sp_window window{};
  if (sp == 0) {
    return window;
  }
  uint64_t clamped_below = below;
  if (sp < clamped_below) {
    clamped_below = sp;
  }
  window.base = sp - clamped_below;
  window.size = clamped_below + above;
  window.below = clamped_below;
  window.above = above;
  return window;
}

sp_window clamp_sp_window(const sp_window& window, uint64_t max_size) {
  if (window.size == 0 || max_size == 0 || window.size <= max_size) {
    return window;
  }

  uint64_t excess = window.size - max_size;
  uint64_t new_above = window.above;
  uint64_t new_below = window.below;

  uint64_t reduce = std::min(new_above, excess);
  new_above -= reduce;
  excess -= reduce;
  if (excess > 0) {
    reduce = std::min(new_below, excess);
    new_below -= reduce;
    excess -= reduce;
  }

  sp_window clamped{};
  clamped.below = new_below;
  clamped.above = new_above;
  clamped.base = window.base + (window.below - new_below);
  clamped.size = new_below + new_above;
  return clamped;
}

uint64_t segment_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

uint64_t overlap_size(const stack_window_segment& a, const stack_window_segment& b) {
  uint64_t a_end = segment_end(a.base, a.size);
  uint64_t b_end = segment_end(b.base, b.size);
  uint64_t start = std::max(a.base, b.base);
  uint64_t end = std::min(a_end, b_end);
  if (start >= end) {
    return 0;
  }
  return end - start;
}

uint64_t byte_size_for_bits(uint16_t bits) { return bits == 0 ? 0u : static_cast<uint64_t>((bits + 7u) / 8u); }

std::optional<uint64_t> read_register_value(
    const w1::util::register_state& regs, const w1::rewind::register_spec* spec
) {
  if (!spec || spec->name.empty()) {
    return std::nullopt;
  }
  uint64_t value = 0;
  if (!regs.get_register(spec->name, value)) {
    return std::nullopt;
  }
  return value;
}

uint64_t resolve_pointer_bytes(const register_schema& schema) {
  if (const auto* sp_spec = schema.find_spec_by_flag(w1::rewind::register_flag_sp)) {
    uint64_t bytes = byte_size_for_bits(sp_spec->bit_size);
    if (bytes != 0) {
      return bytes;
    }
  }
  if (const auto* fp_spec = schema.find_spec_by_flag(w1::rewind::register_flag_fp)) {
    uint64_t bytes = byte_size_for_bits(fp_spec->bit_size);
    if (bytes != 0) {
      return bytes;
    }
  }
  return 0;
}

stack_window_segment make_fp_window(
    const w1::util::register_state& regs, const register_schema& schema, uint64_t pointer_bytes, bool& valid
) {
  stack_window_segment segment{};
  valid = false;
  const auto* fp_spec = schema.find_spec_by_flag(w1::rewind::register_flag_fp);
  auto fp_value = read_register_value(regs, fp_spec);
  if (!fp_value.has_value() || *fp_value == 0) {
    return segment;
  }
  if (pointer_bytes == 0) {
    return segment;
  }

  uint64_t window_bytes = pointer_bytes * 2;
  if (window_bytes == 0) {
    return segment;
  }

  segment.base = *fp_value;
  segment.size = window_bytes;
  valid = true;
  return segment;
}

void merge_segments(std::vector<stack_window_segment>& segments) {
  if (segments.empty()) {
    return;
  }
  std::sort(segments.begin(), segments.end(), [](const auto& left, const auto& right) {
    return left.base < right.base;
  });

  std::vector<stack_window_segment> merged;
  merged.reserve(segments.size());
  stack_window_segment current = segments.front();
  uint64_t current_end = segment_end(current.base, current.size);

  for (size_t i = 1; i < segments.size(); ++i) {
    const auto& next = segments[i];
    uint64_t next_end = segment_end(next.base, next.size);
    if (next.base > current_end) {
      merged.push_back(current);
      current = next;
      current_end = next_end;
      continue;
    }

    current_end = std::max(current_end, next_end);
    current.size = current_end - current.base;
  }

  merged.push_back(current);
  segments.swap(merged);
}

} // namespace

stack_window_result compute_stack_window_segments(
    const w1::util::register_state& regs, const register_schema& schema,
    const rewind_config::stack_window_options& options
) {
  stack_window_result result{};

  if (options.mode == rewind_config::stack_window_options::window_mode::none) {
    return result;
  }

  const auto* sp_spec = schema.find_spec_by_flag(w1::rewind::register_flag_sp);
  auto sp_value = read_register_value(regs, sp_spec);
  if (!sp_value.has_value() || *sp_value == 0) {
    return result;
  }
  uint64_t sp = *sp_value;

  sp_window sp_seg = compute_sp_window(sp, options.above_bytes, options.below_bytes);

  if (options.mode == rewind_config::stack_window_options::window_mode::fixed) {
    sp_seg = clamp_sp_window(sp_seg, options.max_total_bytes);
    if (sp_seg.size > 0) {
      result.segments.push_back(stack_window_segment{sp_seg.base, sp_seg.size});
    }
    return result;
  }

  uint64_t pointer_bytes = resolve_pointer_bytes(schema);
  bool fp_valid = false;
  stack_window_segment fp_seg = make_fp_window(regs, schema, pointer_bytes, fp_valid);
  if (!fp_valid) {
    result.frame_window_missing = true;
  }

  if (options.max_total_bytes > 0) {
    uint64_t max_sp_size = options.max_total_bytes;
    if (fp_valid) {
      uint64_t overlap = overlap_size(stack_window_segment{sp_seg.base, sp_seg.size}, fp_seg);
      uint64_t available = options.max_total_bytes > fp_seg.size ? options.max_total_bytes - fp_seg.size : 0;
      if (sp_seg.size > available + overlap) {
        max_sp_size = available + overlap;
      }
    }
    sp_seg = clamp_sp_window(sp_seg, max_sp_size);
  }

  if (sp_seg.size > 0) {
    result.segments.push_back(stack_window_segment{sp_seg.base, sp_seg.size});
  }
  if (fp_valid && fp_seg.size > 0) {
    result.segments.push_back(fp_seg);
  }

  merge_segments(result.segments);
  return result;
}

} // namespace w1rewind
