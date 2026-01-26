#pragma once

#include <deque>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/mapping_types.hpp"

namespace w1::rewind {

class mapping_state {
public:
  bool reset(std::span<const mapping_record> initial, std::string& error);
  bool apply_event(const mapping_record& record, std::string& error);

  const mapping_record* find_mapping_for_address(
      uint32_t space_id, uint64_t address, uint64_t size, uint64_t& mapping_offset
  ) const;
  const mapping_range* find_mapping_after(uint32_t space_id, uint64_t address) const;

  const std::unordered_map<uint32_t, std::vector<mapping_range>>& ranges_by_space() const { return ranges_by_space_; }

  bool snapshot(std::vector<mapping_record>& out, std::string& error) const;

private:
  bool apply_map(const mapping_record& record, std::string& error);
  bool apply_unmap(const mapping_record& record, std::string& error);
  bool apply_protect(const mapping_record& record, std::string& error);

  std::deque<mapping_record> storage_;
  std::unordered_map<uint32_t, std::vector<mapping_range>> ranges_by_space_;
};

} // namespace w1::rewind
