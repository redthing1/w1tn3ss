#pragma once

#include <redlog.hpp>

namespace w1::cli {

inline redlog::level level_from_verbosity(int count) {
  if (count <= 0) {
    return redlog::level::info;
  }
  if (count == 1) {
    return redlog::level::verbose;
  }
  if (count == 2) {
    return redlog::level::trace;
  }
  if (count == 3) {
    return redlog::level::debug;
  }
  return redlog::level::pedantic;
}

inline void apply_verbosity(int count) { redlog::set_level(level_from_verbosity(count)); }

} // namespace w1::cli
