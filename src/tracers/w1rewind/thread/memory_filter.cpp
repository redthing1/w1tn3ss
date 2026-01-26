#include "memory_filter.hpp"

#include "w1base/interval.hpp"

namespace w1rewind {
memory_filter::memory_filter(const rewind_config::memory_options& options) : ranges_(options.ranges) {
  match_all_ = false;
  use_ranges_ = false;
  use_stack_window_ = false;

  if (options.filters.empty()) {
    match_all_ = true;
  } else {
    for (const auto& filter : options.filters) {
      switch (filter) {
      case rewind_config::memory_filter_kind::all:
        match_all_ = true;
        break;
      case rewind_config::memory_filter_kind::ranges:
        use_ranges_ = true;
        break;
      case rewind_config::memory_filter_kind::stack_window:
        use_stack_window_ = true;
        break;
      default:
        break;
      }
    }
  }

  if (match_all_) {
    use_ranges_ = false;
    use_stack_window_ = false;
  } else if (use_ranges_) {
    w1::util::merge_ranges(ranges_);
  }
}

std::vector<w1::address_range> memory_filter::filter(
    uint64_t address, uint32_t size, std::span<const stack_window_segment> stack_segments
) const {
  std::vector<w1::address_range> out;
  if (size == 0) {
    return out;
  }

  uint64_t end = w1::util::range_end_saturating(address, size);
  w1::address_range event{address, end};

  if (match_all_) {
    out.push_back(event);
    return out;
  }

  std::vector<w1::address_range> selectors;
  if (use_ranges_) {
    selectors.insert(selectors.end(), ranges_.begin(), ranges_.end());
  }
  if (use_stack_window_) {
    selectors.reserve(selectors.size() + stack_segments.size());
    for (const auto& segment : stack_segments) {
      if (segment.size == 0) {
        continue;
      }
      selectors.push_back(w1::address_range{segment.base, w1::util::range_end_saturating(segment.base, segment.size)});
    }
  }

  if (selectors.empty()) {
    return out;
  }

  std::vector<w1::address_range> intersections;
  intersections.reserve(selectors.size());
  for (const auto& range : selectors) {
    uint64_t start = std::max(event.start, range.start);
    uint64_t stop = std::min(event.end, range.end);
    if (start < stop) {
      intersections.push_back(w1::address_range{start, stop});
    }
  }

  if (intersections.empty()) {
    return out;
  }

  w1::util::merge_ranges(intersections);
  return intersections;
}

} // namespace w1rewind
