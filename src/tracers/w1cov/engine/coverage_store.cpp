#include "coverage_store.hpp"

namespace w1cov {

void coverage_store::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  entries_.clear();
}

void coverage_store::record(uint64_t address, uint16_t size, uint16_t module_id, uint32_t hits) {
  if (address == 0 || hits == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  record_locked(address, size, module_id, hits);
}

void coverage_store::merge(const coverage_buffer& buffer) {
  if (buffer.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& [address, entry] : buffer) {
    if (entry.hits == 0 || address == 0) {
      continue;
    }
    record_locked(address, entry.size, entry.module_id, entry.hits);
  }
}

coverage_snapshot coverage_store::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);

  coverage_snapshot snapshot;
  snapshot.units.reserve(entries_.size());

  uint64_t total_hits = 0;
  for (const auto& [address, entry] : entries_) {
    coverage_unit unit{};
    unit.address = address;
    unit.size = entry.size;
    unit.module_id = entry.module_id;
    unit.hitcount = entry.hitcount;
    snapshot.units.push_back(unit);
    total_hits += entry.hitcount;
  }

  snapshot.total_hits = total_hits;
  return snapshot;
}

size_t coverage_store::unit_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return entries_.size();
}

uint64_t coverage_store::total_hits() const {
  std::lock_guard<std::mutex> lock(mutex_);
  uint64_t total = 0;
  for (const auto& [address, entry] : entries_) {
    (void)address;
    total += entry.hitcount;
  }
  return total;
}

void coverage_store::record_locked(uint64_t address, uint16_t size, uint16_t module_id, uint32_t hits) {
  auto& entry = entries_[address];
  if (entry.hitcount == 0) {
    entry.module_id = module_id;
    entry.size = size;
  } else if (entry.size == 0 && size != 0) {
    entry.size = size;
  }

  uint64_t new_total = static_cast<uint64_t>(entry.hitcount) + static_cast<uint64_t>(hits);
  if (new_total > std::numeric_limits<uint32_t>::max()) {
    entry.hitcount = std::numeric_limits<uint32_t>::max();
  } else {
    entry.hitcount = static_cast<uint32_t>(new_total);
  }
}

} // namespace w1cov
