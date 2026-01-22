#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <vector>

#include "w1base/types.hpp"

namespace w1::runtime {

struct module_info {
  std::string name;
  std::string path;
  uint64_t base_address = 0;
  uint64_t size = 0;
  uint32_t permissions = 0;
  bool is_system = false;
  address_range full_range{};
  std::vector<address_range> mapped_ranges;
  std::vector<address_range> exec_ranges;
};

class module_catalog {
public:
  void refresh();
  const module_info* find_containing(uint64_t address) const;
  std::vector<module_info> list_modules() const;
  uint64_t version() const { return version_.load(std::memory_order_acquire); }

private:
  struct range_index_entry {
    address_range range{};
    size_t module_index = 0;
  };

  mutable std::shared_mutex mutex_{};
  std::vector<module_info> modules_;
  std::vector<range_index_entry> range_index_;
  std::atomic<uint64_t> version_{0};
};

} // namespace w1::runtime
