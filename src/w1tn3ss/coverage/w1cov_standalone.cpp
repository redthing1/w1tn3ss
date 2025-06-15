#include "w1cov_standalone.hpp"
#include "../formats/drcov.hpp"
#include "w1cov_constants.hpp"
#include <QBDI.h>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <redlog/redlog.hpp>
#include <sstream>

namespace w1::coverage {

namespace {

// Format numbers with thousands separators
std::string format_number(uint64_t number) {
  try {
    std::stringstream ss;
    ss.imbue(std::locale(""));
    ss << number;
    return ss.str();
  } catch (...) {
    // Fallback to manual formatting
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

// Global coverage instance for callback access
w1cov_standalone* g_current_tracer = nullptr;

// Basic block coverage callback - simple and efficient
QBDI::VMAction coverage_callback(
    QBDI::VMInstanceRef vm, const QBDI::VMState* vmState, QBDI::GPRState* gprState, QBDI::FPRState* fprState, void* data
) {
  if (!vmState || !g_current_tracer) {
    return QBDI::CONTINUE;
  }

  // Record basic block
  uint64_t bb_start = vmState->basicBlockStart;
  uint64_t bb_end = vmState->basicBlockEnd;
  uint16_t bb_size = static_cast<uint16_t>(bb_end - bb_start);

  g_current_tracer->record_basic_block(bb_start, bb_size);

  return QBDI::CONTINUE;
}

} // anonymous namespace

w1cov_standalone::w1cov_standalone() : initialized_(false) {
  auto log = redlog::get_logger("w1cov_standalone");
  log.info("w1cov standalone tracer created");
}

w1cov_standalone::~w1cov_standalone() { shutdown(); }

bool w1cov_standalone::initialize() {
  if (initialized_) {
    return true;
  }

  auto log = redlog::get_logger("w1cov_standalone");
  log.info("initializing w1cov standalone tracer");

  // Clear any existing data
  hitcounts_.clear();
  address_sizes_.clear();

  initialized_ = true;
  g_current_tracer = this;

  log.info("w1cov standalone tracer initialized successfully");
  return true;
}

void w1cov_standalone::shutdown() {
  if (!initialized_) {
    return;
  }

  auto log = redlog::get_logger("w1cov_standalone");
  log.info(
      "shutting down w1cov standalone tracer", redlog::field("unique_blocks", hitcounts_.size()),
      redlog::field("total_hits", get_total_hits())
  );

  g_current_tracer = nullptr;
  initialized_ = false;
}

bool w1cov_standalone::trace_function(void* func_ptr, const std::vector<uint64_t>& args, uint64_t* result) {
  if (!initialized_) {
    auto log = redlog::get_logger("w1cov_standalone");
    log.error("tracer not initialized");
    return false;
  }

  auto log = redlog::get_logger("w1cov_standalone");
  log.info(
      "tracing function", redlog::field("address", reinterpret_cast<uint64_t>(func_ptr)),
      redlog::field("args", args.size())
  );

  try {
    // Create fresh VM for each call
    QBDI::VM vm{};

    // Get GPR state
    QBDI::GPRState* state = vm.getGPRState();
    if (!state) {
      log.error("failed to get GPR state");
      return false;
    }

    // Setup virtual stack
    uint8_t* fakestack;
    if (!QBDI::allocateVirtualStack(state, w1::cov::DEFAULT_STACK_SIZE, &fakestack)) {
      log.error("failed to allocate virtual stack");
      return false;
    }

    // Register coverage callback
    uint32_t cid = vm.addVMEventCB(QBDI::BASIC_BLOCK_ENTRY, coverage_callback, nullptr);
    if (cid == QBDI::INVALID_EVENTID) {
      log.error("failed to register coverage callback");
      QBDI::alignedFree(fakestack);
      return false;
    }

    // Add instrumentation for the function's module
    if (!vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(func_ptr))) {
      log.error("failed to add instrumentation for function");
      QBDI::alignedFree(fakestack);
      return false;
    }

    // Call the function
    QBDI::rword retvalue;
    bool call_success;

    if (args.empty()) {
      call_success = vm.call(&retvalue, reinterpret_cast<QBDI::rword>(func_ptr));
    } else {
      std::vector<QBDI::rword> qbdi_args;
      for (uint64_t arg : args) {
        qbdi_args.push_back(static_cast<QBDI::rword>(arg));
      }
      call_success = vm.call(&retvalue, reinterpret_cast<QBDI::rword>(func_ptr), qbdi_args);
    }

    // Cleanup
    QBDI::alignedFree(fakestack);

    if (!call_success) {
      log.error("function call failed");
      return false;
    }

    if (result) {
      *result = static_cast<uint64_t>(retvalue);
    }

    log.info(
        "function trace completed", redlog::field("return_value", retvalue),
        redlog::field("new_blocks", hitcounts_.size())
    );

    return true;

  } catch (const std::exception& e) {
    log.error("trace function failed", redlog::field("error", e.what()));
    return false;
  }
}

bool w1cov_standalone::trace_address_range(uint64_t start, uint64_t end) {
  if (!initialized_) {
    auto log = redlog::get_logger("w1cov_standalone");
    log.error("tracer not initialized");
    return false;
  }

  auto log = redlog::get_logger("w1cov_standalone");
  log.info("tracing address range", redlog::field("start", start), redlog::field("end", end));

  try {
    // Create fresh VM
    QBDI::VM vm{};

    // Get GPR state
    QBDI::GPRState* state = vm.getGPRState();
    if (!state) {
      log.error("failed to get GPR state");
      return false;
    }

    // Setup virtual stack
    uint8_t* fakestack;
    if (!QBDI::allocateVirtualStack(state, w1::cov::DEFAULT_STACK_SIZE, &fakestack)) {
      log.error("failed to allocate virtual stack");
      return false;
    }

    // Register coverage callback
    uint32_t cid = vm.addVMEventCB(QBDI::BASIC_BLOCK_ENTRY, coverage_callback, nullptr);
    if (cid == QBDI::INVALID_EVENTID) {
      log.error("failed to register coverage callback");
      QBDI::alignedFree(fakestack);
      return false;
    }

    // Add instrumentation for the range
    vm.addInstrumentedRange(start, end);

    // Run the range
    vm.run(start, end);

    // Cleanup
    QBDI::alignedFree(fakestack);

    log.info("address range trace completed", redlog::field("new_blocks", hitcounts_.size()));

    return true;

  } catch (const std::exception& e) {
    log.error("trace address range failed", redlog::field("error", e.what()));
    return false;
  }
}

uint64_t w1cov_standalone::get_total_hits() const {
  uint64_t total = 0;
  for (const auto& [addr, count] : hitcounts_) {
    total += count;
  }
  return total;
}

uint32_t w1cov_standalone::get_hitcount(uint64_t address) const {
  auto it = hitcounts_.find(address);
  return (it != hitcounts_.end()) ? it->second : 0;
}

bool w1cov_standalone::export_drcov(const std::string& filename) const {
  auto log = redlog::get_logger("w1cov_standalone");
  log.info("exporting coverage to drcov format", redlog::field("filename", filename));

  if (hitcounts_.empty()) {
    log.warn("no coverage data to export");
    return false;
  }

  try {
    // Get current process memory maps to find modules
    std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);
    if (maps.empty()) {
      log.error("failed to get process memory maps");
      return false;
    }

    // Filter executable modules
    std::vector<QBDI::MemoryMap> exec_modules;
    for (const auto& map : maps) {
      if (map.permission & QBDI::PF_EXEC) {
        exec_modules.push_back(map);
      }
    }

    if (exec_modules.empty()) {
      log.error("no executable modules found");
      return false;
    }

    // Group coverage by module
    std::unordered_map<const QBDI::MemoryMap*, std::vector<std::tuple<uint64_t, uint16_t, uint32_t>>> module_blocks;
    std::vector<const QBDI::MemoryMap*> module_list;

    for (const auto& [addr, hitcount] : hitcounts_) {
      const QBDI::MemoryMap* module = nullptr;
      for (const auto& map : exec_modules) {
        if (addr >= map.range.start() && addr < map.range.end()) {
          module = &map;
          break;
        }
      }

      if (module) {
        if (module_blocks.find(module) == module_blocks.end()) {
          module_list.push_back(module);
        }
        uint16_t size = address_sizes_.count(addr) ? address_sizes_.at(addr) : 1;
        module_blocks[module].emplace_back(addr, size, hitcount);
      }
    }

    if (module_blocks.empty()) {
      log.error("no coverage data mapped to modules");
      return false;
    }

    // Build DrCov file with hitcount support
    auto builder = drcov::builder().set_module_version(drcov::module_table_version::v2).enable_hitcounts();

    // Add modules
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

    // Write the file
    auto coverage_data = builder.build();
    drcov::write(filename, coverage_data);

    log.info(
        "coverage export successful", redlog::field("filename", filename),
        redlog::field("modules", module_blocks.size()), redlog::field("blocks", hitcounts_.size()),
        redlog::field("total_hits", get_total_hits())
    );

    return true;

  } catch (const std::exception& e) {
    log.error("coverage export failed", redlog::field("error", e.what()));
    return false;
  }
}

void w1cov_standalone::print_summary() const {
  auto log = redlog::get_logger("w1cov_standalone");

  uint64_t total_hits = get_total_hits();

  log.info("Coverage Summary:");
  log.info("  Unique Basic Blocks: " + format_number(hitcounts_.size()));
  log.info("  Total Hits:          " + format_number(total_hits));

  if (!hitcounts_.empty()) {
    // Find min/max hitcounts for statistics
    auto [min_it, max_it] = std::minmax_element(hitcounts_.begin(), hitcounts_.end(), [](const auto& a, const auto& b) {
      return a.second < b.second;
    });

    double avg_hits = static_cast<double>(total_hits) / hitcounts_.size();

    log.info("  Average Hits/Block:  " + std::to_string(avg_hits));
    log.info("  Min Hits:            " + format_number(min_it->second));
    log.info("  Max Hits:            " + format_number(max_it->second));
  }
}

void w1cov_standalone::record_basic_block(uint64_t address, uint16_t size) {
  hitcounts_[address]++;
  address_sizes_[address] = size;
}

} // namespace w1::coverage