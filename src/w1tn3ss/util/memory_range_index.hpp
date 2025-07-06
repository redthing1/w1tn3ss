#pragma once

#include <QBDI.h>
#include <QBDI/Memory.h>
#include "interval_tree.hpp"
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <redlog.hpp>

namespace w1::util {

// Memory region information
struct memory_region {
  QBDI::rword start;
  QBDI::rword end;
  uint32_t permissions; // QBDI_PF_READ, QBDI_PF_WRITE, QBDI_PF_EXEC
  std::string name;     // Module name if applicable
};

// Fast memory range validation using interval tree
class memory_range_index {
public:
  using memory_interval = interval_tree::interval<QBDI::rword, memory_region>;

  enum access_type { READ = QBDI::QBDI_PF_READ, WRITE = QBDI::QBDI_PF_WRITE, EXEC = QBDI::QBDI_PF_EXEC };

  memory_range_index() : log_("w1.memory_range_index") {}

  // Main API: Check if access would succeed
  // If check fails, automatically refreshes mappings and tries again
  bool check_access(QBDI::rword address, size_t size, access_type type) const;

  // Find region containing address
  const memory_region* find_region(QBDI::rword address) const;

  // Force refresh of memory mappings
  void refresh();

  // Check if we have any mappings loaded
  bool empty() const;

private:
  mutable std::shared_mutex mutex_;
  mutable interval_tree::interval_tree<QBDI::rword, memory_region> tree_;
  mutable bool initialized_ = false;
  mutable std::chrono::steady_clock::time_point last_refresh_;
  static constexpr auto min_refresh_interval = std::chrono::milliseconds(100);
  redlog::logger log_;

  // Check access without refresh
  bool check_access_internal(QBDI::rword address, size_t size, uint32_t perms) const;

  // Internal refresh
  void refresh_internal() const;
};

} // namespace w1::util