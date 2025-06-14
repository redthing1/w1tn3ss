#pragma once

#include <memory>
#include <redlog/redlog.hpp>
#include <string>
#include <vector>

// forward declarations for QBDI types
namespace QBDI {
struct MemoryMap;
}

namespace w1::coverage {

class coverage_collector;

struct memory_region {
  uint64_t start;
  uint64_t end;
  std::string name;
  std::string permission;
  bool is_executable;

  memory_region(uint64_t s, uint64_t e, const std::string& n, const std::string& perm, bool exec)
      : start(s), end(e), name(n), permission(perm), is_executable(exec) {}

  uint64_t size() const { return end - start; }
  bool contains(uint64_t addr) const { return addr >= start && addr < end; }
};

class module_mapper {
public:
  module_mapper(coverage_collector& collector);
  ~module_mapper();

  // module discovery and registration
  bool discover_process_modules();
  bool discover_qbdi_modules();
  size_t register_discovered_modules();

  // module queries
  const memory_region* find_region_by_address(uint64_t address) const;
  std::vector<memory_region> get_executable_regions() const;
  std::vector<memory_region> get_user_modules() const;

  // configuration
  void set_exclude_system_modules(bool exclude) { exclude_system_ = exclude; }
  void add_target_module_pattern(const std::string& pattern);
  void clear_target_patterns();

  // statistics
  size_t get_total_regions() const { return regions_.size(); }
  size_t get_executable_count() const;
  size_t get_user_module_count() const;

private:
  redlog::logger log_;
  coverage_collector& collector_;
  std::vector<memory_region> regions_;
  std::vector<std::string> target_patterns_;
  bool exclude_system_;

  // platform-specific implementations
  bool discover_modules_unix();
  bool discover_modules_darwin();
  bool discover_modules_linux();
  bool discover_modules_windows();
  bool discover_memory_regions_windows();

  // helper methods
  bool is_system_module(const std::string& path) const;
  bool matches_target_pattern(const std::string& path) const;
  bool should_include_module(const memory_region& region) const;
  std::string parse_permissions(const std::string& perm_str) const;

  // qbdi integration
  bool convert_qbdi_memory_maps(const std::vector<QBDI::MemoryMap>& maps);
};

} // namespace w1::coverage