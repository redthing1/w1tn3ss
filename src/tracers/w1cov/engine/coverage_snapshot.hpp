#pragma once

#include <cstdint>
#include <vector>

namespace w1cov {

struct coverage_unit {
  uint64_t address = 0;
  uint16_t size = 0;
  uint16_t module_id = 0;
  uint32_t hitcount = 0;
};

struct coverage_snapshot {
  std::vector<coverage_unit> units;
  uint64_t total_hits = 0;
};

} // namespace w1cov
