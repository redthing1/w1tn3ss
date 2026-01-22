#pragma once

#include <cstdint>
#include <limits>
#include <mutex>
#include <unordered_map>

#include "engine/coverage_snapshot.hpp"

namespace w1cov {

struct coverage_buffer_entry {
  uint16_t module_id = 0;
  uint16_t size = 0;
  uint32_t hits = 0;
};

using coverage_buffer = std::unordered_map<uint64_t, coverage_buffer_entry>;

class coverage_store {
public:
  void reset();

  void record(uint64_t address, uint16_t size, uint16_t module_id, uint32_t hits = 1);
  void merge(const coverage_buffer& buffer);

  coverage_snapshot snapshot() const;
  size_t unit_count() const;
  uint64_t total_hits() const;

private:
  struct coverage_entry {
    uint16_t module_id = 0;
    uint16_t size = 0;
    uint32_t hitcount = 0;
  };

  void record_locked(uint64_t address, uint16_t size, uint16_t module_id, uint32_t hits);

  mutable std::mutex mutex_{};
  std::unordered_map<uint64_t, coverage_entry> entries_{};
};

} // namespace w1cov
