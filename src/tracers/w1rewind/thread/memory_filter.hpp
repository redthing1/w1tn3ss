#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "config/rewind_config.hpp"
#include "stack_window_policy.hpp"
#include "w1base/types.hpp"

namespace w1rewind {

class memory_filter {
public:
  explicit memory_filter(const rewind_config::memory_options& options);

  bool matches_all() const { return match_all_; }
  bool uses_ranges() const { return use_ranges_; }
  bool uses_stack_window() const { return use_stack_window_; }
  const std::vector<w1::address_range>& ranges() const { return ranges_; }

  std::vector<w1::address_range> filter(
      uint64_t address, uint32_t size, std::span<const stack_window_segment> stack_segments
  ) const;

private:
  bool match_all_ = true;
  bool use_ranges_ = false;
  bool use_stack_window_ = false;
  std::vector<w1::address_range> ranges_{};
};

} // namespace w1rewind
