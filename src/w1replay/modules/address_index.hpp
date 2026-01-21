#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "w1rewind/replay/replay_context.hpp"

namespace w1replay {

struct module_address_match {
  const w1::rewind::module_record* module = nullptr;
  uint64_t module_offset = 0;
};

class module_address_index {
public:
  explicit module_address_index(const w1::rewind::replay_context& context);

  std::optional<module_address_match> find(uint64_t address, uint64_t size) const;

private:
  struct address_range {
    uint64_t start = 0;
    uint64_t end = 0;
    const w1::rewind::module_record* module = nullptr;
  };

  std::optional<module_address_match> find_in_ranges(
      const std::vector<address_range>& ranges, uint64_t address, uint64_t end
  ) const;

  std::vector<address_range> region_ranges_;
  std::vector<address_range> module_ranges_;
};

} // namespace w1replay
