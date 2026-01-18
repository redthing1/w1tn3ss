#pragma once

#include <cstdint>

namespace w1 {

struct address_range {
  uint64_t start = 0;
  uint64_t end = 0;
};

} // namespace w1
