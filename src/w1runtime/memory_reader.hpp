#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include <QBDI.h>
#include <QBDI/Memory.hpp>

namespace w1 {
namespace runtime {
class module_catalog;
} // namespace runtime

namespace util {

class memory_reader {
public:
  explicit memory_reader(QBDI::VM* vm, const runtime::module_catalog& modules) : vm_(vm), modules_(&modules) {}

  std::optional<std::vector<uint8_t>> read_bytes(uint64_t address, size_t size) const;
  std::optional<std::string> read_string(uint64_t address, size_t max_len) const;

private:
  bool is_readable_range(uint64_t address, uint64_t end) const;
  bool is_readable_range_locked(uint64_t address, uint64_t end) const;
  void refresh_maps(bool force) const;

  QBDI::VM* vm_ = nullptr;
  const runtime::module_catalog* modules_ = nullptr;
  mutable std::shared_mutex maps_mutex_{};
  mutable std::vector<QBDI::MemoryMap> readable_maps_{};
  mutable std::chrono::steady_clock::time_point last_refresh_{};
  static constexpr auto min_refresh_interval = std::chrono::milliseconds(100);
};

} // namespace util
} // namespace w1
