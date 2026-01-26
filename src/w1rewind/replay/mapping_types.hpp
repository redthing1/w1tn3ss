#pragma once

#include <cstdint>

namespace w1::rewind {

struct mapping_record;

struct mapping_range {
  uint64_t start = 0;
  uint64_t end = 0;
  const mapping_record* mapping = nullptr;
};

} // namespace w1::rewind
