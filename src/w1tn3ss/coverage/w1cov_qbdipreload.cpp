/**
 * w1cov QBDIPreload Coverage Tracer
 *
 * Coverage collection using QBDI for launch-time instrumentation.
 * Exports DrCov format for analysis tools.
 *
 * Environment variables:
 * - W1COV_ENABLED: Set to "1" to enable coverage collection
 * - W1COV_OUTPUT_FILE: Output file path (default: w1cov.drcov)
 * - W1COV_DEBUG: Set to "1" for verbose debug output
 */

#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "../formats/drcov.hpp"
#include "QBDIPreload.h"
#include "w1cov_constants.hpp"
#include <QBDI.h>

namespace w1cov {

/**
 * Format number with thousands separator for readability
 */
std::string format_number(uint64_t number) {
  try {
    std::stringstream ss;
    ss.imbue(std::locale(""));
    ss << number;
    return ss.str();
  } catch (...) {
    // Fallback to manual formatting if locale fails
    std::string result = std::to_string(number);
    std::string formatted;
    int count = 0;
    for (int i = result.length() - 1; i >= 0; --i) {
      if (count && count % 3 == 0) {
        formatted = ',' + formatted;
      }
      formatted = result[i] + formatted;
      count++;
    }
    return formatted;
  }
}

/**
 * Global state management for coverage collection.
 * Uses lazy initialization to avoid C++ global constructor issues in injection context.
 */

static bool g_enabled = false;
static bool g_debug_mode = false;
static uint64_t g_basic_block_count = 0;

// Lazy-initialized containers to avoid global constructor issues
static std::unordered_map<uint64_t, uint32_t>* get_hitcounts() {
  static std::unordered_map<uint64_t, uint32_t> instance;
  return &instance;
}

static std::unordered_map<uint64_t, uint16_t>* get_address_sizes() {
  static std::unordered_map<uint64_t, uint16_t> instance;
  return &instance;
}

static std::vector<QBDI::MemoryMap>* get_modules() {
  static std::vector<QBDI::MemoryMap> instance;
  return &instance;
}

static std::string* get_output_file() {
  static std::string instance = w1::cov::DEFAULT_OUTPUT_FILENAME;
  return &instance;
}

/**
 * Check if w1cov is enabled.
 * @return true if coverage collection is enabled, false otherwise
 */
bool is_enabled() { return g_enabled; }

/**
 * Check if w1cov debug mode is enabled.
 * @return true if debug mode is enabled, false otherwise
 */
bool is_debug_mode() { return g_debug_mode; }

/**
 * Configure coverage collection from environment variables.
 * Called during library initialization.
 */
void configure_from_env() {
  const char* enabled = getenv(w1::cov::ENV_W1COV_ENABLED);
  g_enabled = (enabled && strcmp(enabled, w1::cov::ENABLED_VALUE) == 0);

  const char* output = getenv(w1::cov::ENV_W1COV_OUTPUT_FILE);
  if (output) {
    *get_output_file() = output;
  }

  const char* debug = getenv(w1::cov::ENV_W1COV_DEBUG);
  g_debug_mode = (debug && strcmp(debug, w1::cov::ENABLED_VALUE) == 0);

  if (g_debug_mode) {
    w1::cov::log("Configuration: enabled=%d, output=%s, debug=%d", g_enabled, get_output_file()->c_str(), g_debug_mode);
  }
}

/**
 * Discover executable modules in the target process.
 * Uses QBDI memory mapping for cross-platform module discovery.
 */
bool discover_modules() {
  std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);

  if (maps.empty()) {
    if (g_debug_mode) {
      w1::cov::log("Failed to get process memory maps");
    }
    return false;
  }

  // Filter and store executable modules
  auto* modules = get_modules();
  for (const auto& map : maps) {
    if (map.permission & QBDI::PF_EXEC) {
      modules->push_back(map);
      if (g_debug_mode) {
        w1::cov::log(
            "Module: %s [0x%llx-0x%llx] %s", map.name.c_str(), map.range.start(), map.range.end(),
            (map.permission & QBDI::PF_EXEC) ? "X" : "-"
        );
      }
    }
  }

  if (g_debug_mode) {
    w1::cov::log("Discovered %s executable modules", format_number(modules->size()).c_str());
  }

  return !modules->empty();
}

/**
 * Find the module containing a specific address.
 * Required for DrCov export which needs module-relative offsets.
 */
const QBDI::MemoryMap* find_module_for_address(uint64_t addr) {
  auto* modules = get_modules();
  for (const auto& module : *modules) {
    if (addr >= module.range.start() && addr < module.range.end()) {
      return &module;
    }
  }
  return nullptr;
}

/**
 * QBDI basic block callback for coverage collection.
 * Invoked for every basic block entry, much more efficient than instruction-level tracing.
 */
QBDI::VMAction coverage_callback(
    QBDI::VMInstanceRef vm, const QBDI::VMState* vmState, QBDI::GPRState* gprState, QBDI::FPRState* fprState, void* data
) {
  if (!vmState) {
    return QBDI::CONTINUE;
  }

  g_basic_block_count++;

  // Get basic block start address and size
  uint64_t bb_start = vmState->basicBlockStart;
  uint64_t bb_end = vmState->basicBlockEnd;
  uint16_t bb_size = static_cast<uint16_t>(bb_end - bb_start);

  // Record basic block for coverage analysis
  (*get_hitcounts())[bb_start]++;
  (*get_address_sizes())[bb_start] = bb_size;

  // Periodic progress reporting for long-running analyses
  if (g_debug_mode && (g_basic_block_count % w1::cov::PROGRESS_REPORT_INTERVAL == 0)) {
    w1::cov::log(
        "Traced %s basic blocks, %s unique blocks", format_number(g_basic_block_count).c_str(),
        format_number(get_hitcounts()->size()).c_str()
    );
  }

  return QBDI::CONTINUE;
}

/**
 * Export collected coverage data in DrCov format.
 * Compatible with Lighthouse, IDA Pro, and Binary Ninja analysis tools.
 */
bool export_drcov_coverage() {
  auto* hitcounts = get_hitcounts();
  auto* address_sizes = get_address_sizes();

  if (hitcounts->empty()) {
    if (g_debug_mode) {
      w1::cov::log("No coverage data to export");
    }
    return false;
  }

  // Group coverage data by module for DrCov format
  std::unordered_map<const QBDI::MemoryMap*, std::vector<std::tuple<uint64_t, uint16_t, uint32_t>>> module_blocks;
  std::vector<const QBDI::MemoryMap*> module_list;

  for (const auto& [addr, hitcount] : *hitcounts) {
    const QBDI::MemoryMap* module = find_module_for_address(addr);
    if (module) {
      if (module_blocks.find(module) == module_blocks.end()) {
        module_list.push_back(module);
      }
      uint16_t size = address_sizes->count(addr) ? (*address_sizes)[addr] : 1;
      module_blocks[module].emplace_back(addr, size, hitcount);
    }
  }

  if (module_blocks.empty()) {
    if (g_debug_mode) {
      w1::cov::log("No coverage data mapped to modules");
    }
    return false;
  }

  try {
    // Build DrCov file with hitcount support
    auto builder = drcov::builder().enable_hitcounts().set_module_version(drcov::module_table_version::v2);

    // Add module table
    for (const QBDI::MemoryMap* module : module_list) {
      std::string module_name = module->name.empty() ? "unknown" : module->name;
      builder.add_module(module_name, module->range.start(), module->range.end(), 0);
    }

    // Add coverage blocks with hitcounts
    uint16_t module_id = 0;
    for (const QBDI::MemoryMap* module : module_list) {
      const auto& blocks = module_blocks[module];
      for (const auto& block : blocks) {
        uint64_t addr = std::get<0>(block);
        uint16_t size = std::get<1>(block);
        uint32_t hitcount = std::get<2>(block);
        uint32_t offset = static_cast<uint32_t>(addr - module->range.start());
        builder.add_coverage(module_id, offset, size, hitcount);
      }
      module_id++;
    }

    auto coverage_data = builder.build();
    drcov::write(*get_output_file(), coverage_data);

    uint64_t total_hits = 0;
    for (const auto& [addr, hitcount] : *hitcounts) {
      total_hits += hitcount;
    }

    w1::cov::log("Coverage Summary:");
    w1::cov::log("        Basic Blocks: %s", format_number(hitcounts->size()).c_str());
    w1::cov::log("        Total Hits:   %s", format_number(total_hits).c_str());
    w1::cov::log("        Modules:      %s", format_number(module_blocks.size()).c_str());
    w1::cov::log("Coverage exported -> %s", get_output_file()->c_str());

    return true;

  } catch (const std::exception& e) {
    w1::cov::log("Failed to export coverage: %s", e.what());
    return false;
  }
}

} // namespace w1cov
extern "C" {

QBDIPRELOAD_INIT;

int qbdipreload_on_start(void* main) {
  // Always print something to verify library is loaded
  w1::cov::log("qbdipreload_on_start called");

  w1cov::configure_from_env();

  if (!w1cov::g_enabled) {
    w1::cov::log("w1cov not enabled, exiting");
    return QBDIPRELOAD_NOT_HANDLED;
  }

  w1::cov::log("w1cov enabled, continuing");
  return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

int qbdipreload_on_main(int argc, char** argv) {
  if (!w1cov::g_enabled) {
    return QBDIPRELOAD_NOT_HANDLED;
  }

  if (w1cov::g_debug_mode) {
    w1::cov::log("qbdipreload_on_main: initializing module discovery");
  }

  // Discover modules early
  if (!w1cov::discover_modules()) {
    w1::cov::log("Failed to discover modules");
    return QBDIPRELOAD_NOT_HANDLED;
  }

  return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  if (!w1cov::g_enabled) {
    vm->run(start, stop);
    return QBDIPRELOAD_NO_ERROR;
  }

  if (w1cov::g_debug_mode) {
    w1::cov::log("qbdipreload_on_run: start=0x%llx, stop=0x%llx", start, stop);
  }

  // Register basic block coverage callback (much more efficient than instruction-level)
  vm->addVMEventCB(QBDI::BASIC_BLOCK_ENTRY, w1cov::coverage_callback, nullptr);

  if (w1cov::g_debug_mode) {
    w1::cov::log("Coverage callback registered, starting instrumentation");
  }

  // Run with instrumentation
  vm->run(start, stop);

  if (w1cov::g_debug_mode) {
    w1::cov::log("Instrumentation completed");
  }

  return QBDIPRELOAD_NO_ERROR;
}

int qbdipreload_on_exit(int status) {
  if (!w1cov::g_enabled) {
    return QBDIPRELOAD_NO_ERROR;
  }

  if (w1cov::g_debug_mode) {
    w1::cov::log("qbdipreload_on_exit: exporting coverage data");
  }

  // Export coverage
  w1cov::export_drcov_coverage();

  if (w1cov::g_debug_mode) {
    w1::cov::log("w1cov coverage collection completed");
  }

  return QBDIPRELOAD_NO_ERROR;
}

} // extern "C"