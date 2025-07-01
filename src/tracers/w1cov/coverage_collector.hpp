#pragma once

#include <w1tn3ss/util/module_info.hpp>
#include <w1tn3ss/formats/drcov.hpp>
#include <vector>
#include <unordered_map>
#include <QBDI.h>

namespace w1cov {

struct basic_block_info {
  QBDI::rword address;
  uint16_t size;
  uint16_t module_id;
  uint32_t hitcount;
};

class coverage_collector {
public:
  coverage_collector();

  uint16_t add_module(const w1::util::module_info& mod);

  void record_basic_block(QBDI::rword address, uint16_t size, uint16_t module_id);

  drcov::coverage_data build_drcov_data() const;

  size_t get_basic_block_count() const;
  size_t get_module_count() const;
  uint64_t get_total_hits() const;
  uint32_t get_hitcount(QBDI::rword address) const;
  const w1::util::module_info* find_module_by_id(uint16_t id) const;

private:
  std::vector<w1::util::module_info> modules_;
  std::unordered_map<QBDI::rword, size_t> address_to_bb_index_;
  std::vector<basic_block_info> basic_blocks_;
  std::unordered_map<QBDI::rword, uint32_t> hitcounts_;
};

} // namespace w1cov