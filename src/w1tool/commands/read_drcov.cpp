#include "read_drcov.hpp"
#include "../../w1tn3ss/formats/drcov.hpp"
#include <iomanip>
#include <iostream>
#include <redlog/redlog.hpp>

namespace w1tool::commands {

int read_drcov(
    args::ValueFlag<std::string>& file_flag, args::Flag& summary_flag, args::Flag& detailed_flag,
    args::ValueFlag<std::string>& module_flag
) {

  auto log = redlog::get_logger("w1tool.read-drcov");

  if (!file_flag) {
    log.error("DrCov file path required");
    return 1;
  }

  std::string file_path = args::get(file_flag);
  log.info("analyzing DrCov file", redlog::field("file", file_path));

  try {
    // Read and parse the DrCov file
    auto coverage_data = drcov::read(file_path);

    // Print header information
    std::cout << "=== DrCov File Analysis ===\n";
    std::cout << "File: " << file_path << "\n";
    std::cout << "Version: " << coverage_data.header.version << "\n";
    std::cout << "Flavor: " << coverage_data.header.flavor << "\n";
    std::cout << "Module Table Version: " << static_cast<uint32_t>(coverage_data.module_version) << "\n";
    std::cout << "\n";

    // Print summary
    std::cout << "=== Summary ===\n";
    std::cout << "Total Modules: " << coverage_data.modules.size() << "\n";
    std::cout << "Total Basic Blocks: " << coverage_data.basic_blocks.size() << "\n";

    // Calculate coverage stats
    auto stats = coverage_data.get_coverage_stats();
    uint64_t total_coverage_bytes = 0;
    for (const auto& bb : coverage_data.basic_blocks) {
      total_coverage_bytes += bb.size;
    }
    std::cout << "Total Coverage: " << total_coverage_bytes << " bytes\n";
    std::cout << "\n";

    // Module summary
    std::cout << "=== Module Coverage ===\n";
    std::cout << std::left << std::setw(4) << "ID" << std::setw(8) << "Blocks" << std::setw(12) << "Size"
              << std::setw(20) << "Base Address"
              << "Name\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& module : coverage_data.modules) {
      auto it = stats.find(module.id);
      size_t block_count = (it != stats.end()) ? it->second : 0;

      // Calculate total bytes for this module
      uint64_t module_bytes = 0;
      for (const auto& bb : coverage_data.basic_blocks) {
        if (bb.module_id == module.id) {
          module_bytes += bb.size;
        }
      }

      std::cout << std::left << std::setw(4) << module.id << std::setw(8) << block_count << std::setw(12)
                << (std::to_string(module_bytes) + " bytes") << "0x" << std::hex << std::setw(18) << module.base
                << std::dec << module.path << "\n";
    }
    std::cout << "\n";

    // Detailed analysis if requested
    if (detailed_flag) {
      std::cout << "=== Detailed Basic Blocks ===\n";
      std::cout << std::left << std::setw(6) << "Module" << std::setw(12) << "Offset" << std::setw(8) << "Size"
                << "Absolute Address\n";
      std::cout << std::string(40, '-') << "\n";

      for (const auto& bb : coverage_data.basic_blocks) {
        if (bb.module_id < coverage_data.modules.size()) {
          const auto& module = coverage_data.modules[bb.module_id];
          uint64_t abs_addr = bb.absolute_address(module);

          std::cout << std::left << std::setw(6) << bb.module_id << "0x" << std::hex << std::setw(10) << bb.start
                    << std::dec << std::setw(8) << bb.size << "0x" << std::hex << abs_addr << std::dec << "\n";
        }
      }
      std::cout << "\n";
    }

    // Module-specific analysis if requested
    if (module_flag) {
      std::string module_filter = args::get(module_flag);
      std::cout << "=== Module-Specific Analysis: " << module_filter << " ===\n";

      // Find matching modules (by name substring)
      bool found = false;
      for (const auto& module : coverage_data.modules) {
        if (module.path.find(module_filter) != std::string::npos) {
          found = true;

          std::cout << "Module ID: " << module.id << "\n";
          std::cout << "Name: " << module.path << "\n";
          std::cout << "Base: 0x" << std::hex << module.base << std::dec << "\n";
          std::cout << "End: 0x" << std::hex << module.end << std::dec << "\n";
          std::cout << "Size: " << (module.end - module.base) << " bytes\n";

          // Count blocks for this module
          auto it = stats.find(module.id);
          size_t block_count = (it != stats.end()) ? it->second : 0;
          std::cout << "Covered Blocks: " << block_count << "\n";

          uint64_t module_bytes = 0;
          for (const auto& bb : coverage_data.basic_blocks) {
            if (bb.module_id == module.id) {
              module_bytes += bb.size;
            }
          }
          std::cout << "Covered Bytes: " << module_bytes << "\n";
          std::cout << "\n";
        }
      }

      if (!found) {
        std::cout << "No modules found matching: " << module_filter << "\n";
      }
    }

    return 0;

  } catch (const drcov::parse_error& e) {
    log.error(
        "failed to parse DrCov file", redlog::field("error", e.what()),
        redlog::field("code", static_cast<int>(e.code()))
    );
    return 1;
  } catch (const std::exception& e) {
    log.error("error analyzing DrCov file", redlog::field("error", e.what()));
    return 1;
  }
}

} // namespace w1tool::commands