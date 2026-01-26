#pragma once

#include <algorithm>
#include <cstdint>

namespace w1::rewind {

inline uint64_t pe_section_mem_size(uint64_t virtual_size, uint64_t raw_size) {
  return std::max<uint64_t>(virtual_size, raw_size);
}

} // namespace w1::rewind
