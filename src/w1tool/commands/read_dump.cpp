#include "read_dump.hpp"
#include <w1tn3ss/dump/process_dumper.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <chrono>
#include <redlog.hpp>

namespace w1tool::commands {

using namespace w1::dump;

// helper function to format timestamp
std::string format_timestamp(uint64_t timestamp) {
  // timestamp is in milliseconds since epoch
  auto duration = std::chrono::milliseconds(timestamp);
  auto tp = std::chrono::system_clock::time_point(duration);
  auto time_t = std::chrono::system_clock::to_time_t(tp);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
  return ss.str();
}

// helper function to format byte sizes
static std::string format_bytes_dump(uint64_t bytes) {
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

// helper to format permissions
std::string format_permissions(uint32_t perms) {
  std::string result;
  result += (perms & 1) ? "r" : "-"; // read
  result += (perms & 2) ? "w" : "-"; // write
  result += (perms & 4) ? "x" : "-"; // execute
  return result;
}

int read_dump(
    args::ValueFlag<std::string>& file_flag, args::Flag& detailed_flag, args::ValueFlag<std::string>& module_flag
) {
  auto log = redlog::get_logger("w1tool.read_dump");

  if (!file_flag) {
    log.err("--file argument required");
    return 1;
  }

  std::string file_path = args::get(file_flag);

  try {
    // load the dump
    auto dump = w1::dump::process_dumper::load_dump(file_path);

    // always show the metadata overview
    {
      // better organized output
      std::cout << "W1DUMP Process Snapshot\n";
      std::cout << "═══════════════════════\n";

      // metadata section
      std::cout << "├─ Metadata\n";
      std::cout << "│  ├─ Timestamp: " << format_timestamp(dump.metadata.timestamp) << "\n";
      std::cout << "│  ├─ Platform:  " << dump.metadata.os << "/" << dump.metadata.arch << " ("
                << static_cast<int>(dump.metadata.pointer_size) * 8 << "-bit)\n";
      std::cout << "│  └─ Process:   " << dump.metadata.process_name << " [pid:" << dump.metadata.pid << "]\n";

      // module statistics
      size_t user_modules = 0;
      size_t system_modules = 0;
      for (const auto& mod : dump.modules) {
        if (mod.is_system) {
          system_modules++;
        } else {
          user_modules++;
        }
      }

      std::cout << "├─ Modules (" << dump.modules.size() << " total)\n";
      std::cout << "│  ├─ User:   " << user_modules << "\n";
      std::cout << "│  └─ System: " << system_modules << "\n";

      // memory statistics with proper calculation
      size_t stack_count = 0, code_count = 0, data_count = 0;
      uint64_t stack_size = 0, code_size = 0, data_size = 0;
      size_t mapped_regions = 0;
      size_t reserved_regions = 0;

      for (const auto& region : dump.regions) {
        uint64_t size = region.end - region.start;

        // count mapped vs reserved regions
        if (region.permissions != 0) {
          mapped_regions++;

          if (region.is_stack) {
            stack_count++;
            stack_size += size;
          } else if (region.is_code) {
            code_count++;
            code_size += size;
          } else if (region.is_data) {
            data_count++;
            data_size += size;
          }
        } else {
          reserved_regions++;
        }
      }

      uint64_t total_mapped = stack_size + code_size + data_size;

      std::cout << "├─ Memory Regions (" << dump.regions.size() << " total, " << mapped_regions << " mapped)\n";
      std::cout << "│  ├─ Stack: " << std::setw(3) << stack_count << " regions (" << format_bytes_dump(stack_size)
                << ")\n";
      std::cout << "│  ├─ Code:  " << std::setw(3) << code_count << " regions (" << format_bytes_dump(code_size)
                << ")\n";
      std::cout << "│  ├─ Data:  " << std::setw(3) << data_count << " regions (" << format_bytes_dump(data_size)
                << ")\n";
      std::cout << "│  └─ Total: " << format_bytes_dump(total_mapped) << " mapped\n";

      // thread state
      std::cout << "└─ Thread State\n";
      std::cout << "   ├─ Thread ID: " << dump.thread.thread_id << "\n";
      std::cout << "   ├─ Registers: " << dump.thread.gpr_values.size() << " GPR, " << dump.thread.fpr_values.size()
                << " FPR\n";
      std::cout << "   └─ Captured:  " << (dump.regions.size() > 0 ? "✓" : "✗") << " memory, "
                << (!dump.thread.gpr_values.empty() ? "✓" : "✗") << " registers\n";
    }

    // show detailed view - compact and information-dense
    if (detailed_flag) {
      // filter by module if specified
      std::string module_filter;
      if (module_flag) {
        module_filter = args::get(module_flag);
      }

      // modules section
      std::cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
      std::cout << "MODULES (" << dump.modules.size() << " total)\n";
      std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

      // collect modules by type for better organization
      std::vector<const module_info*> user_mods, system_mods;
      for (const auto& mod : dump.modules) {
        if (!module_filter.empty() && mod.name.find(module_filter) == std::string::npos) {
          continue;
        }

        if (mod.is_system) {
          system_mods.push_back(&mod);
        } else {
          user_mods.push_back(&mod);
        }
      }

      // compact module display
      auto print_module_line = [](const module_info* mod, bool show_system) {
        std::cout << std::hex << std::setw(12) << mod->base_address << std::dec << " " << std::setw(8) << std::right
                  << format_bytes_dump(mod->size) << " " << std::setw(3) << format_permissions(mod->permissions) << " "
                  << std::left << std::setw(32) << mod->name;
        if (show_system) {
          std::cout << " [sys]";
        }
        std::cout << "\n";
      };

      // headers
      std::cout << "BASE         SIZE     PRM NAME\n";
      std::cout << "────────────────────────────────────────────────────────────────────────────────────────────────\n";

      // user modules first
      for (const auto* mod : user_mods) {
        print_module_line(mod, false);
      }

      // separator if both exist
      if (!user_mods.empty() && !system_mods.empty()) {
        std::cout
            << "── system ──────────────────────────────────────────────────────────────────────────────────────\n";
      }

      // system modules
      for (const auto* mod : system_mods) {
        print_module_line(mod, true);
      }

      // memory regions section
      std::cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
      std::cout << "MEMORY REGIONS (" << dump.regions.size() << " total)\n";
      std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

      // group regions by type
      struct RegionGroup {
        std::string name;
        std::vector<const memory_region*> regions;
        uint64_t total_size = 0;
      };

      RegionGroup stack{"STACK", {}, 0};
      RegionGroup code{"CODE", {}, 0};
      RegionGroup data{"DATA", {}, 0};

      for (const auto& region : dump.regions) {
        if (region.permissions == 0) {
          continue; // skip unmapped
        }

        uint64_t size = region.end - region.start;
        if (region.is_stack) {
          stack.regions.push_back(&region);
          stack.total_size += size;
        } else if (region.is_code) {
          code.regions.push_back(&region);
          code.total_size += size;
        } else if (region.is_data) {
          data.regions.push_back(&region);
          data.total_size += size;
        }
      }

      // headers
      std::cout << "START        END          SIZE     PRM TYPE MODULE\n";
      std::cout << "────────────────────────────────────────────────────────────────────────────────────────────────\n";

      auto print_region_group = [](const RegionGroup& group) {
        if (group.regions.empty()) {
          return;
        }

        std::cout << "── " << group.name << " (" << group.regions.size() << " regions, "
                  << format_bytes_dump(group.total_size) << ") ";
        for (int i = 0; i < 70 - group.name.length() - 20; i++) {
          std::cout << "─";
        }
        std::cout << "\n";

        for (const auto* region : group.regions) {
          std::cout << std::hex << std::setw(12) << region->start << " " << std::setw(12) << region->end << std::dec
                    << " " << std::setw(8) << format_bytes_dump(region->end - region->start) << " " << std::setw(3)
                    << format_permissions(region->permissions) << " " << std::setw(4)
                    << (region->is_stack  ? "STK"
                        : region->is_code ? "CODE"
                                          : "DATA");

          if (!region->module_name.empty() && region->module_name.find("_unnamed") == std::string::npos) {
            std::cout << " " << region->module_name;
          }

          if (!region->data.empty()) {
            std::cout << " [" << format_bytes_dump(region->data.size()) << " captured]";
          }

          std::cout << "\n";
        }
      };

      print_region_group(stack);
      print_region_group(code);
      print_region_group(data);
    }

  } catch (const std::exception& e) {
    log.err("failed to read dump", redlog::field("file", file_path), redlog::field("error", e.what()));
    return 1;
  }

  return 0;
}

} // namespace w1tool::commands
