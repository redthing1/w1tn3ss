#include "read_drcov.hpp"
#include <w1formats/drcov.hpp>
#include <iomanip>
#include <iostream>
#include <locale>
#include <redlog.hpp>
#include <sstream>

namespace w1tool::commands {

std::string format_address(uint64_t address) {
  std::ostringstream out;
  out << "0x" << std::hex << address;
  return out.str();
}

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

std::string format_average(double value) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(2) << value;
  return out.str();
}

int read_drcov(
    args::ValueFlag<std::string>& file_flag, args::Flag& summary_flag, args::Flag& detailed_flag,
    args::ValueFlag<std::string>& module_flag
) {

  auto log = redlog::get_logger("w1tool.read-drcov");

  if (!file_flag) {
    log.error("drCov file path required");
    return 1;
  }

  std::string file_path = args::get(file_flag);
  log.info("analyzing DrCov file", redlog::field("file", file_path));

  try {
    // read and parse the DrCov file
    auto coverage_data = drcov::read(file_path);

    const bool has_hitcounts = coverage_data.has_hitcounts();

    std::cout << "drcov:\n";
    std::cout << "  file=" << file_path << "\n";
    std::cout << "  version=" << coverage_data.header.version << "\n";
    std::cout << "  flavor=" << coverage_data.header.flavor << "\n";
    std::cout << "  module_version=" << static_cast<uint32_t>(coverage_data.module_version) << "\n";
    std::cout << "  hitcounts=" << (has_hitcounts ? "yes" : "no") << "\n";
    std::cout << "\n";

    // calculate coverage stats
    uint64_t total_coverage_bytes = 0;
    uint64_t total_hitcount = 0;

    for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
      const auto& bb = coverage_data.basic_blocks[i];
      total_coverage_bytes += bb.size;

      if (has_hitcounts && i < coverage_data.hitcounts.size()) {
        total_hitcount += coverage_data.hitcounts[i];
      }
    }

    std::cout << "summary:\n";
    std::cout << "  modules=" << format_number(coverage_data.modules.size())
              << " blocks=" << format_number(coverage_data.basic_blocks.size()) << "\n";
    std::cout << "  coverage=" << format_bytes(total_coverage_bytes);
    if (has_hitcounts) {
      double avg_hits = coverage_data.basic_blocks.empty()
                            ? 0.0
                            : static_cast<double>(total_hitcount) / coverage_data.basic_blocks.size();
      std::cout << " hits=" << format_hits(total_hitcount) << " avg_hits=" << format_average(avg_hits);
    }
    std::cout << "\n\n";

    if (summary_flag) {
      return 0;
    }

    auto stats = coverage_data.get_coverage_stats();

    // module summary
    std::cout << "modules:\n";
    if (coverage_data.modules.empty()) {
      std::cout << "  none\n\n";
    } else {
      std::cout << "  " << std::left << std::setw(4) << "id" << std::setw(8) << "blocks" << std::setw(12) << "size";
      if (has_hitcounts) {
        std::cout << std::setw(10) << "hits";
      }
      std::cout << std::setw(18) << "base"
                << "name\n";
    }

    if (!coverage_data.modules.empty()) {
      for (const auto& module : coverage_data.modules) {
        auto it = stats.find(module.id);
        size_t block_count = (it != stats.end()) ? it->second : 0;

        uint64_t module_bytes = 0;
        uint64_t module_hits = 0;

        for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
          const auto& bb = coverage_data.basic_blocks[i];
          if (bb.module_id == module.id) {
            module_bytes += bb.size;
            if (has_hitcounts && i < coverage_data.hitcounts.size()) {
              module_hits += coverage_data.hitcounts[i];
            }
          }
        }

        std::cout << "  " << std::left << std::setw(4) << module.id << std::setw(8) << format_number(block_count)
                  << std::setw(12) << format_bytes(module_bytes);
        if (has_hitcounts) {
          std::cout << std::setw(10) << format_hits(module_hits);
        }
        std::cout << std::setw(18) << format_address(module.base) << module.path << "\n";
      }
      std::cout << "\n";
    }

    // detailed analysis if requested
    if (detailed_flag) {
      std::cout << "blocks:\n";
      if (coverage_data.basic_blocks.empty()) {
        std::cout << "  none\n\n";
      } else {
        std::cout << "  " << std::left << std::setw(8) << "module" << std::setw(14) << "offset" << std::setw(8)
                  << "size";
        if (has_hitcounts) {
          std::cout << std::setw(10) << "hits";
        }
        std::cout << std::setw(18) << "addr"
                  << "name\n";

        for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
          const auto& bb = coverage_data.basic_blocks[i];
          if (bb.module_id < coverage_data.modules.size()) {
            const auto& module = coverage_data.modules[bb.module_id];
            uint64_t abs_addr = bb.absolute_address(module);

            std::cout << "  " << std::left << std::setw(8) << bb.module_id << std::setw(14) << format_address(bb.start)
                      << std::setw(8) << bb.size;
            if (has_hitcounts && i < coverage_data.hitcounts.size()) {
              std::cout << std::setw(10) << coverage_data.hitcounts[i];
            }
            std::cout << std::setw(18) << format_address(abs_addr) << module.path << "\n";
          }
        }
        std::cout << "\n";
      }
    }

    // module-specific analysis if requested
    if (module_flag) {
      std::string module_filter = args::get(module_flag);
      std::cout << "module:\n";
      std::cout << "  filter=" << module_filter << "\n";

      // find matching modules (by name substring)
      bool found = false;
      for (const auto& module : coverage_data.modules) {
        if (module.path.find(module_filter) != std::string::npos) {
          found = true;

          // count blocks for this module
          auto it = stats.find(module.id);
          size_t block_count = (it != stats.end()) ? it->second : 0;

          uint64_t module_bytes = 0;
          uint64_t module_hits = 0;

          for (size_t i = 0; i < coverage_data.basic_blocks.size(); ++i) {
            const auto& bb = coverage_data.basic_blocks[i];
            if (bb.module_id == module.id) {
              module_bytes += bb.size;
              if (has_hitcounts && i < coverage_data.hitcounts.size()) {
                module_hits += coverage_data.hitcounts[i];
              }
            }
          }

          std::cout << "  id=" << module.id << " name=" << module.path << "\n";
          std::cout << "  base=" << format_address(module.base) << " end=" << format_address(module.end)
                    << " size=" << format_bytes(module.end - module.base) << "\n";
          std::cout << "  blocks=" << format_number(block_count) << " coverage=" << format_bytes(module_bytes);
          if (has_hitcounts) {
            double avg_hits = (block_count == 0) ? 0.0 : static_cast<double>(module_hits) / block_count;
            std::cout << " hits=" << format_hits(module_hits) << " avg_hits=" << format_average(avg_hits);
          }
          std::cout << "\n\n";
        }
      }

      if (!found) {
        std::cout << "  result=none\n";
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
