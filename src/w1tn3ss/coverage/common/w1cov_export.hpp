#pragma once

#include "../../formats/drcov.hpp"
#include "w1cov_config.hpp"
#include <QBDI.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace w1::coverage {

/// Coverage data statistics
struct coverage_statistics {
  size_t total_basic_blocks = 0;
  size_t total_coverage_bytes = 0;
  size_t instrumented_modules = 0;
};

/// DrCov format exporter for coverage data
class coverage_exporter {
public:
  /// Initialize exporter with tool identification
  explicit coverage_exporter(const std::string& tool_flavor_name);

  /// Configure exporter with coverage settings
  void configure_with_settings(const coverage_config& config);

  /// Register modules that were instrumented
  void register_instrumented_modules(const std::vector<QBDI::MemoryMap>& discovered_modules);

  /// Record all covered addresses at once
  void record_covered_addresses(const std::unordered_set<uint64_t>& covered_addresses);

  /// Record single covered address during instrumentation
  void record_single_covered_address(uint64_t absolute_address);

  /// Export collected coverage to DrCov file
  bool export_coverage_to_drcov_file(const std::string& output_file_path);

  /// Get current coverage statistics
  coverage_statistics get_coverage_statistics() const;

  /// Reset all collected data
  void reset_collected_data();

private:
  /// Tool identifier for DrCov flavor field
  std::string exporter_tool_name_;

  /// Coverage configuration settings
  coverage_config current_config_;

  /// Modules that were instrumented
  std::vector<QBDI::MemoryMap> instrumented_modules_;

  /// All addresses that were covered during execution
  std::unordered_set<uint64_t> covered_addresses_;

  /// Group covered addresses by their containing modules
  void organize_addresses_by_containing_modules(std::unordered_map<size_t, std::vector<uint64_t>>& addresses_per_module
  ) const;

  /// Find which module contains a specific address
  const QBDI::MemoryMap* find_module_containing_address(uint64_t target_address) const;

  /// Get display name for module based on config
  std::string get_module_name_for_export(const QBDI::MemoryMap& module) const;
};

} // namespace w1::coverage