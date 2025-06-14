#include "w1cov_export.hpp"
#include "w1cov_qbdi_utils.hpp"
#include <algorithm>

namespace w1::coverage {

coverage_exporter::coverage_exporter(const std::string& tool_flavor_name) : exporter_tool_name_(tool_flavor_name) {}

void coverage_exporter::configure_with_settings(const coverage_config& config) { current_config_ = config; }

void coverage_exporter::register_instrumented_modules(const std::vector<QBDI::MemoryMap>& discovered_modules) {
  instrumented_modules_ = discovered_modules;
}

void coverage_exporter::record_covered_addresses(const std::unordered_set<uint64_t>& covered_addresses) {
  covered_addresses_ = covered_addresses;
}

void coverage_exporter::record_single_covered_address(uint64_t absolute_address) {
  covered_addresses_.insert(absolute_address);
}

bool coverage_exporter::export_coverage_to_drcov_file(const std::string& output_file_path) {
  try {
    // Organize covered addresses by the modules that contain them
    std::unordered_map<size_t, std::vector<uint64_t>> addresses_per_module;
    organize_addresses_by_containing_modules(addresses_per_module);

    // Initialize DrCov format builder
    auto drcov_builder =
        drcov::builder().set_flavor(exporter_tool_name_).set_module_version(drcov::module_table_version::v2);

    // Add all instrumented modules to DrCov data
    for (size_t module_index = 0; module_index < instrumented_modules_.size(); ++module_index) {
      const auto& current_module = instrumented_modules_[module_index];
      std::string module_name_for_export = get_module_name_for_export(current_module);

      drcov_builder.add_module(
          module_name_for_export, current_module.range.start(), current_module.range.end(),
          current_module.range.start() // entry point
      );
    }

    // Add all covered basic blocks to DrCov data
    for (const auto& [module_index, covered_addresses_in_module] : addresses_per_module) {
      if (module_index >= instrumented_modules_.size()) {
        continue; // Skip invalid module references
      }

      const auto& containing_module = instrumented_modules_[module_index];

      for (uint64_t covered_address : covered_addresses_in_module) {
        // Verify address is within module bounds
        bool address_is_within_module =
            (covered_address >= containing_module.range.start()) && (covered_address < containing_module.range.end());
        if (!address_is_within_module) {
          continue;
        }

        uint32_t offset_from_module_base = static_cast<uint32_t>(covered_address - containing_module.range.start());
        uint16_t basic_block_size = 4; // Standard instruction size

        drcov_builder.add_coverage(static_cast<uint16_t>(module_index), offset_from_module_base, basic_block_size);
      }
    }

    // Generate final DrCov data and write to file
    auto final_coverage_data = drcov_builder.build();
    drcov::write(output_file_path, final_coverage_data);

    return true;

  } catch (const std::exception& export_error) {
    output::injection_safe_printf("[W1COV] Export failed: %s\n", export_error.what());
    return false;
  }
}

coverage_statistics coverage_exporter::get_coverage_statistics() const {
  coverage_statistics stats;
  stats.total_basic_blocks = covered_addresses_.size();
  stats.total_coverage_bytes = stats.total_basic_blocks * 4; // Standard instruction size
  stats.instrumented_modules = instrumented_modules_.size();
  return stats;
}

void coverage_exporter::reset_collected_data() {
  instrumented_modules_.clear();
  covered_addresses_.clear();
}

void coverage_exporter::organize_addresses_by_containing_modules(
    std::unordered_map<size_t, std::vector<uint64_t>>& addresses_per_module
) const {

  // For each covered address, find which module contains it
  for (uint64_t covered_address : covered_addresses_) {
    const QBDI::MemoryMap* containing_module = find_module_containing_address(covered_address);
    if (!containing_module) {
      continue; // Address not in any known module
    }

    // Find the index of this module in our instrumented modules list
    for (size_t module_index = 0; module_index < instrumented_modules_.size(); ++module_index) {
      if (&instrumented_modules_[module_index] == containing_module) {
        addresses_per_module[module_index].push_back(covered_address);
        break;
      }
    }
  }

  // Sort addresses within each module for consistent output
  for (auto& [module_index, address_list] : addresses_per_module) {
    std::sort(address_list.begin(), address_list.end());
  }
}

const QBDI::MemoryMap* coverage_exporter::find_module_containing_address(uint64_t target_address) const {
  for (const auto& module : instrumented_modules_) {
    bool address_is_in_this_module = (target_address >= module.range.start()) && (target_address < module.range.end());
    if (address_is_in_this_module) {
      return &module;
    }
  }
  return nullptr;
}

std::string coverage_exporter::get_module_name_for_export(const QBDI::MemoryMap& module) const {
  return modules::get_module_display_name(module.name, current_config_.should_track_full_module_paths);
}

} // namespace w1::coverage