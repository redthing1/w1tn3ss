#pragma once

#include <cstdint>
#include <vector>

#include "config/rewind_config.hpp"
#include "w1runtime/register_capture.hpp"

namespace w1rewind {

struct stack_window_segment {
  uint64_t base = 0;
  uint64_t size = 0;
};

struct stack_window_result {
  std::vector<stack_window_segment> segments;
  bool frame_window_missing = false;
};

stack_window_result compute_stack_window_segments(
    const w1::util::register_state& regs, const rewind_config::stack_window_options& options
);

} // namespace w1rewind
