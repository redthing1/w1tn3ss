#include "read_dump.hpp"
#include <w1dump/process_dumper.hpp>
#include <iomanip>
#include <iostream>
#include <redlog.hpp>

#include "w1base/format_utils.hpp"
#include "w1base/time_utils.hpp"

namespace w1tool::commands {

using namespace w1::dump;

int read_dump(
    args::ValueFlag<std::string>& file_flag, args::Flag& detailed_flag, args::ValueFlag<std::string>& module_flag
) {
  auto log = redlog::get_logger("w1tool.read_dump");

  auto format_perm_bits = [](uint32_t perms) {
    return w1::util::format_permissions((perms & 1u) != 0, (perms & 2u) != 0, (perms & 4u) != 0);
  };

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
      std::cout << "│  ├─ Timestamp: " << w1::util::format_timestamp_local_ms(dump.metadata.timestamp) << "\n";
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

      std::cout << "├─ Memory Regions (" << dump.regions.size() << " total, " << mapped_regions << " mapped, "
                << reserved_regions << " reserved)\n";
      std::cout << "│  ├─ Stack: " << std::setw(3) << stack_count << " regions (" << w1::util::format_bytes(stack_size)
                << ")\n";
      std::cout << "│  ├─ Code:  " << std::setw(3) << code_count << " regions (" << w1::util::format_bytes(code_size)
                << ")\n";
      std::cout << "│  ├─ Data:  " << std::setw(3) << data_count << " regions (" << w1::util::format_bytes(data_size)
                << ")\n";
      std::cout << "│  └─ Total: " << w1::util::format_bytes(total_mapped) << " mapped\n";

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
      auto print_module_line = [&](const module_info* mod, bool show_system) {
        std::cout << std::hex << std::setw(12) << mod->base_address << std::dec << " " << std::setw(8) << std::right
                  << w1::util::format_bytes(mod->size) << " " << std::setw(3) << format_perm_bits(mod->permissions)
                  << " " << std::left << std::setw(32) << mod->name;
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

      auto print_region_group = [&](const RegionGroup& group) {
        if (group.regions.empty()) {
          return;
        }

        std::cout << "── " << group.name << " (" << group.regions.size() << " regions, "
                  << w1::util::format_bytes(group.total_size) << ") ";
        size_t padding = 0;
        const size_t base_width = 70;
        const size_t used_width = group.name.length() + 20;
        if (base_width > used_width) {
          padding = base_width - used_width;
        }
        for (size_t i = 0; i < padding; ++i) {
          std::cout << "─";
        }
        std::cout << "\n";

        for (const auto* region : group.regions) {
          std::cout << std::hex << std::setw(12) << region->start << " " << std::setw(12) << region->end << std::dec
                    << " " << std::setw(8) << w1::util::format_bytes(region->end - region->start) << " " << std::setw(3)
                    << format_perm_bits(region->permissions) << " " << std::setw(4)
                    << (region->is_stack  ? "STK"
                        : region->is_code ? "CODE"
                                          : "DATA");

          if (!region->module_name.empty() && region->module_name.find("_unnamed") == std::string::npos) {
            std::cout << " " << region->module_name;
          }

          if (!region->data.empty()) {
            std::cout << " [" << w1::util::format_bytes(region->data.size()) << " captured]";
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
