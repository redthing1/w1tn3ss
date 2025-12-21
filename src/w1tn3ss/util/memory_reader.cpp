#include "w1tn3ss/util/memory_reader.hpp"

#include <algorithm>
#include <cstring>

#include "w1tn3ss/util/interval.hpp"

namespace w1::util {

std::optional<std::vector<uint8_t>> memory_reader::read_bytes(uint64_t address, size_t size) const {
  if (address == 0) {
    return std::nullopt;
  }

  if (size == 0) {
    return std::vector<uint8_t>{};
  }

  uint64_t end = 0;
  if (!compute_end(address, size, &end)) {
    return std::nullopt;
  }

  refresh_maps(false);
  if (!is_readable_range(address, end)) {
    refresh_maps(true);
    if (!is_readable_range(address, end)) {
      return std::nullopt;
    }
  }

  std::vector<uint8_t> data(size);
  std::memcpy(data.data(), reinterpret_cast<const void*>(address), size);
  return data;
}

std::optional<std::string> memory_reader::read_string(uint64_t address, size_t max_len) const {
  if (address == 0) {
    return std::nullopt;
  }

  if (max_len == 0) {
    return std::string{};
  }

  auto bytes = read_bytes(address, max_len);
  if (!bytes) {
    return std::nullopt;
  }

  auto end = std::find(bytes->begin(), bytes->end(), '\0');
  return std::string(bytes->begin(), end);
}

bool memory_reader::is_readable_range(uint64_t address, uint64_t end) const {
  std::shared_lock lock(maps_mutex_);
  return is_readable_range_locked(address, end);
}

bool memory_reader::is_readable_range_locked(uint64_t address, uint64_t end) const {
  if (address >= end) {
    return false;
  }

  auto it = std::upper_bound(
      readable_maps_.begin(), readable_maps_.end(), address,
      [](uint64_t value, const QBDI::MemoryMap& map) { return value < map.range.start(); }
  );

  if (it == readable_maps_.begin()) {
    return false;
  }

  --it;
  if (address < it->range.start() || end > it->range.end()) {
    return false;
  }

  return true;
}

void memory_reader::refresh_maps(bool force) const {
  auto now = std::chrono::steady_clock::now();
  {
    std::shared_lock lock(maps_mutex_);
    if (!force && !readable_maps_.empty() && (now - last_refresh_) < min_refresh_interval) {
      return;
    }
  }

  auto maps = QBDI::getCurrentProcessMaps(true);
  std::vector<QBDI::MemoryMap> readable;
  readable.reserve(maps.size());

  for (const auto& map : maps) {
    if (map.permission & QBDI::PF_READ) {
      readable.push_back(map);
    }
  }

  std::sort(readable.begin(), readable.end(), [](const QBDI::MemoryMap& left, const QBDI::MemoryMap& right) {
    return left.range.start() < right.range.start();
  });

  std::unique_lock lock(maps_mutex_);
  readable_maps_ = std::move(readable);
  last_refresh_ = now;
}

} // namespace w1::util
