#pragma once

#include "../../formats/drcov.hpp"
#include <cstdint>
#include <mutex>
#include <redlog/redlog.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace w1::coverage {

struct basic_block_info {
  uint64_t address;   // absolute address of basic block
  uint16_t size;      // size in bytes
  uint16_t module_id; // id of containing module

  basic_block_info(uint64_t addr, uint16_t sz, uint16_t mod_id) : address(addr), size(sz), module_id(mod_id) {}
};

struct module_info {
  uint16_t id;           // unique module identifier
  std::string path;      // file system path
  uint64_t base_address; // base address in memory
  uint64_t end_address;  // end address in memory
  uint64_t entry_point;  // entry point (usually 0 for libraries)

  module_info(uint16_t module_id, const std::string& module_path, uint64_t base, uint64_t end, uint64_t entry = 0)
      : id(module_id), path(module_path), base_address(base), end_address(end), entry_point(entry) {}

  uint64_t size() const { return end_address - base_address; }
  bool contains_address(uint64_t addr) const { return addr >= base_address && addr < end_address; }

  uint32_t relative_offset(uint64_t absolute_addr) const {
    if (!contains_address(absolute_addr)) {
      return 0;
    }
    return static_cast<uint32_t>(absolute_addr - base_address);
  }
};

class coverage_collector {
public:
  coverage_collector();
  ~coverage_collector();

  // module management
  uint16_t add_module(const std::string& path, uint64_t base, uint64_t end, uint64_t entry = 0);
  const module_info* find_module_by_address(uint64_t address) const;
  const module_info* find_module_by_id(uint16_t id) const;

  // basic block tracking
  void record_basic_block(uint64_t address, uint16_t size = 1);
  void record_basic_block_with_module(uint64_t address, uint16_t size, uint16_t module_id);

  // statistics and export
  size_t get_total_blocks() const;
  size_t get_unique_blocks() const;
  std::unordered_map<uint16_t, size_t> get_coverage_stats() const;
  
  // hitcount access
  uint32_t get_hitcount(uint64_t address) const;
  uint64_t get_total_hits() const;
  const std::unordered_map<uint64_t, uint32_t>& get_hitcounts() const;

  // drcov export
  drcov::coverage_data export_drcov_data() const;
  bool write_drcov_file(const std::string& filepath) const;

  // configuration
  void set_exclude_system_modules(bool exclude) { exclude_system_ = exclude; }
  void set_output_file(const std::string& filepath) { output_file_ = filepath; }

private:
  mutable std::mutex mutex_;
  redlog::logger log_;

  // module tracking
  std::vector<module_info> modules_;
  std::unordered_map<uint64_t, uint16_t> address_to_module_;
  uint16_t next_module_id_;

  // coverage tracking
  std::unordered_set<uint64_t> covered_addresses_;
  std::vector<basic_block_info> basic_blocks_;
  std::unordered_map<uint64_t, uint32_t> hitcounts_;

  // configuration
  bool exclude_system_;
  std::string output_file_;

  // helper methods
  bool is_system_module(const std::string& path) const;
  uint16_t find_or_create_module_for_address(uint64_t address);
  
  // internal methods (caller must hold mutex_)
  const module_info* find_module_by_address_internal(uint64_t address) const;
  void record_basic_block_with_module_internal(uint64_t address, uint16_t size, uint16_t module_id);
};


} // namespace w1::coverage