#include "read_drcov.hpp"
#include "../../w1tn3ss/formats/drcov.hpp"
#include <iomanip>
#include <iostream>
#include <locale>
#include <redlog/redlog.hpp>
#include <sstream>

namespace w1tool::commands {

// helper function to format hit counts with K/M/B suffixes
std::string format_hits(uint64_t hits) {
  if (hits >= 1000000000) {
    double b = static_cast<double>(hits) / 1000000000.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << b << "B";
    return ss.str();
  } else if (hits >= 1000000) {
    double m = static_cast<double>(hits) / 1000000.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << m << "M";
    return ss.str();
  } else if (hits >= 1000) {
    double k = static_cast<double>(hits) / 1000.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << k << "K";
    return ss.str();
  } else {
    return std::to_string(hits);
  }
}

// helper function to format byte sizes with KB/MB/GB suffixes
std::string format_bytes(uint64_t bytes) {
  if (bytes >= 1024ULL * 1024 * 1024) {
    double gb = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << gb << " GB";
    return ss.str();
  } else if (bytes >= 1024 * 1024) {
    double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << mb << " MB";
    return ss.str();
  } else if (bytes >= 1024) {
    double kb = static_cast<double>(bytes) / 1024.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << kb << " KB";
    return ss.str();
  } else {
    return std::to_string(bytes) + " B";
  }
}

// helper function to format plain numbers (for counts)
std::string format_number(uint64_t number) {
  try {
    std::stringstream ss;
    ss.imbue(std::locale(""));
    ss << number;
    return ss.str();
  } catch (...) {
    // fallback: manual formatting with commas
    std::string str = std::to_string(number);
    std::string result;
    int count = 0;
    for (auto it = str.rbegin(); it != str.rend(); ++it) {
      if (count > 0 && count % 3 == 0) {
        result = ',' + result;
      }
      result = *it + result;
      count++;
    }
    return result;
  }
}

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
    std::cout << "Has Hitcounts: " << (coverage_data.has_hitcounts() ? "Yes" : "No") << "\n";
    std::cout << "\n";

    // Print summary
    std::cout << "=== Summary ===\n";
    std::cout << "Total Modules: " << format_number(coverage_data.modules.size()) << "\n";
    std::cout << "Total Basic Blocks: " << format_number(coverage_data.basic_blocks.size()) << "\n";

    // Calculate coverage stats
    auto stats = coverage_data.get_coverage_stats();
    uint64_t total_coverage_bytes = 0;
    uint64_t total_hitcount = 0;

    for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
      const auto& bb = coverage_data.basic_blocks[i];
      total_coverage_bytes += bb.size;

      if (coverage_data.has_hitcounts() && i < coverage_data.hitcounts.size()) {
        total_hitcount += coverage_data.hitcounts[i];
      }
    }

    std::cout << "Total Coverage: " << format_bytes(total_coverage_bytes) << "\n";
    if (coverage_data.has_hitcounts()) {
      std::cout << "Total Hits: " << format_hits(total_hitcount) << "\n";
      std::cout << "Average Hits per Block: " << std::fixed << std::setprecision(2)
                << (coverage_data.basic_blocks.empty()
                        ? 0.0
                        : static_cast<double>(total_hitcount) / coverage_data.basic_blocks.size())
                << "\n";
    }
    std::cout << "\n";

    // Module summary
    std::cout << "=== Module Coverage ===\n";
    if (coverage_data.has_hitcounts()) {
      std::cout << std::left << std::setw(4) << "ID" << std::setw(8) << "Blocks" << std::setw(12) << "Size"
                << std::setw(12) << "Total Hits" << std::setw(20) << "Base Address"
                << "Name\n";
      std::cout << std::string(72, '-') << "\n";
    } else {
      std::cout << std::left << std::setw(4) << "ID" << std::setw(8) << "Blocks" << std::setw(12) << "Size"
                << std::setw(20) << "Base Address"
                << "Name\n";
      std::cout << std::string(60, '-') << "\n";
    }

    for (const auto& module : coverage_data.modules) {
      auto it = stats.find(module.id);
      size_t block_count = (it != stats.end()) ? it->second : 0;

      // Calculate total bytes and hits for this module
      uint64_t module_bytes = 0;
      uint64_t module_hits = 0;

      for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
        const auto& bb = coverage_data.basic_blocks[i];
        if (bb.module_id == module.id) {
          module_bytes += bb.size;
          if (coverage_data.has_hitcounts() && i < coverage_data.hitcounts.size()) {
            module_hits += coverage_data.hitcounts[i];
          }
        }
      }

      if (coverage_data.has_hitcounts()) {
        std::cout << std::left << std::setw(4) << module.id << std::setw(8) << format_number(block_count)
                  << std::setw(12) << format_bytes(module_bytes) << std::setw(12) << format_hits(module_hits) << "0x"
                  << std::hex << std::setw(15) << module.base << std::dec << "         " << module.path << "\n";
      } else {
        std::cout << std::left << std::setw(4) << module.id << std::setw(8) << format_number(block_count)
                  << std::setw(12) << format_bytes(module_bytes) << "0x" << std::hex << std::setw(15) << module.base
                  << std::dec << "         " << module.path << "\n";
      }
    }
    std::cout << "\n";

    // Detailed analysis if requested
    if (detailed_flag) {
      std::cout << "=== Detailed Basic Blocks ===\n";
      if (coverage_data.has_hitcounts()) {
        std::cout << std::left << std::setw(8) << "Module" << std::setw(14) << "Offset" << std::setw(8) << "Size"
                  << std::setw(10) << "Hitcount" << std::setw(18) << "Absolute Address"
                  << "Module Name\n";
        std::cout << std::string(90, '-') << "\n";
      } else {
        std::cout << std::left << std::setw(8) << "Module" << std::setw(14) << "Offset" << std::setw(8) << "Size"
                  << std::setw(18) << "Absolute Address"
                  << "Module Name\n";
        std::cout << std::string(80, '-') << "\n";
      }

      for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
        const auto& bb = coverage_data.basic_blocks[i];
        if (bb.module_id < coverage_data.modules.size()) {
          const auto& module = coverage_data.modules[bb.module_id];
          uint64_t abs_addr = bb.absolute_address(module);

          if (coverage_data.has_hitcounts() && i < coverage_data.hitcounts.size()) {
            uint32_t hitcount = coverage_data.hitcounts[i];
            std::cout << std::left << std::setw(8) << bb.module_id << "0x" << std::hex << std::setw(11) << bb.start
                      << std::dec << std::setw(8) << bb.size << std::setw(10) << hitcount << "0x" << std::hex
                      << std::setw(15) << abs_addr << std::dec << "   " << module.path << "\n";
          } else {
            std::cout << std::left << std::setw(8) << bb.module_id << "0x" << std::hex << std::setw(11) << bb.start
                      << std::dec << std::setw(8) << bb.size << "0x" << std::hex << std::setw(15) << abs_addr
                      << std::dec << "   " << module.path << "\n";
          }
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
          std::cout << "Covered Blocks: " << format_number(block_count) << "\n";

          uint64_t module_bytes = 0;
          uint64_t module_hits = 0;

          for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
            const auto& bb = coverage_data.basic_blocks[i];
            if (bb.module_id == module.id) {
              module_bytes += bb.size;
              if (coverage_data.has_hitcounts() && i < coverage_data.hitcounts.size()) {
                module_hits += coverage_data.hitcounts[i];
              }
            }
          }

          std::cout << "Covered Bytes: " << format_bytes(module_bytes) << "\n";
          if (coverage_data.has_hitcounts()) {
            std::cout << "Total Hits: " << format_hits(module_hits) << "\n";
            std::cout << "Average Hits per Block: " << std::fixed << std::setprecision(2)
                      << (block_count == 0 ? 0.0 : static_cast<double>(module_hits) / block_count) << "\n";
          }
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