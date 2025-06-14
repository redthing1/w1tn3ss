/**
 * W1COV QBDIPreload Coverage Tracer
 * 
 * Coverage collection using QBDI for launch-time instrumentation.
 * Exports DrCov format for analysis tools.
 * 
 * Environment variables:
 * - W1COV_ENABLED: Set to "1" to enable coverage collection
 * - W1COV_OUTPUT_FILE: Output file path (default: w1cov.drcov)
 * - W1COV_DEBUG: Set to "1" for verbose debug output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <atomic>

#include "QBDIPreload.h"
#include <QBDI.h>
#include "../formats/drcov.hpp"

namespace w1cov {

/**
 * Global state management for coverage collection.
 * Uses lazy initialization pattern to avoid C++ global constructor issues
 * in DYLD_INSERT_LIBRARIES context where C++ runtime may not be fully initialized.
 */

static bool g_enabled = false;
static bool g_debug_mode = false;
static uint64_t g_instruction_count = 0;

// Lazy-initialized complex objects using static local variables
static std::unordered_set<uint64_t>* get_covered_addresses() {
    static std::unordered_set<uint64_t> instance;
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
    static std::string instance = "w1cov.drcov";
    return &instance;
}

/**
 * Configure coverage collection from environment variables.
 * Called during library initialization to establish runtime configuration.
 */
void configure_from_env() {
    const char* enabled = getenv("W1COV_ENABLED");
    g_enabled = (enabled && strcmp(enabled, "1") == 0);
    
    const char* output = getenv("W1COV_OUTPUT_FILE");
    if (output) {
        *get_output_file() = output;
    }
    
    const char* debug = getenv("W1COV_DEBUG");
    g_debug_mode = (debug && strcmp(debug, "1") == 0);
    
    if (g_debug_mode) {
        printf("[W1COV] Configuration: enabled=%d, output=%s, debug=%d\n", 
               g_enabled, get_output_file()->c_str(), g_debug_mode);
    }
}

/**
 * Discover and catalog all executable modules in the target process.
 * Uses QBDI memory mapping to identify loadable modules and their address ranges.
 * Essential for accurate address-to-module mapping during coverage export.
 * 
 * @return true if executable modules were discovered, false on failure
 */
bool discover_modules() {
    // Query process memory maps using QBDI's cross-platform interface
    std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);
    
    if (maps.empty()) {
        if (g_debug_mode) {
            printf("[W1COV] Failed to get process memory maps\n");
        }
        return false;
    }
    
    // Filter and store only executable modules for coverage analysis
    auto* modules = get_modules();
    for (const auto& map : maps) {
        if (map.permission & QBDI::PF_EXEC) {
            modules->push_back(map);
            if (g_debug_mode) {
                printf("[W1COV] Module: %s [0x%llx-0x%llx] %s\n",
                       map.name.c_str(), map.range.start(), map.range.end(),
                       (map.permission & QBDI::PF_EXEC) ? "X" : "-");
            }
        }
    }
    
    if (g_debug_mode) {
        printf("[W1COV] Discovered %zu executable modules\n", modules->size());
    }
    
    return !modules->empty();
}

/**
 * Locate the executable module containing a specific memory address.
 * Performs linear search through discovered modules to map addresses to their containing binaries.
 * Essential for DrCov export format which requires module-relative address offsets.
 * 
 * @param addr Virtual memory address to locate
 * @return Pointer to module containing the address, or nullptr if not found
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
 * QBDI instrumentation callback for real-time coverage collection.
 * Invoked for every instruction executed under QBDI instrumentation.
 * Collects basic block entry points and instruction sizes for accurate coverage mapping.
 * 
 * Implementation follows proven working pattern from QBDI tracer examples.
 * Optimized for minimal runtime overhead during target program execution.
 * 
 * @param vm QBDI virtual machine instance providing instrumentation context
 * @param gprState General-purpose register state (unused)
 * @param fprState Floating-point register state (unused)
 * @param data User-provided callback data (unused)
 * @return QBDI::CONTINUE to allow normal execution flow
 */
QBDI::VMAction coverage_callback(QBDI::VMInstanceRef vm, 
                                QBDI::GPRState *gprState,
                                QBDI::FPRState *fprState, 
                                void *data) {
    // Extract instruction analysis from QBDI virtual machine
    const QBDI::InstAnalysis *instAnalysis = 
        vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    
    if (instAnalysis) {
        uint64_t addr = instAnalysis->address;
        uint16_t size = instAnalysis->instSize;
        
        // Record unique instruction addresses for basic block coverage
        get_covered_addresses()->insert(addr);
        (*get_address_sizes())[addr] = size;
        
        g_instruction_count++;
        
        // Periodic progress reporting for long-running analyses
        if (g_debug_mode && (g_instruction_count % 10000 == 0)) {
            printf("[W1COV] Traced %llu instructions, %zu unique addresses\n",
                   g_instruction_count, get_covered_addresses()->size());
        }
    }
    
    return QBDI::CONTINUE;
}

/**
 * Export collected coverage data in industry-standard DrCov format.
 * 
 * Uses the common drcov.hpp library for consistent format writing across
 * all w1tn3ss coverage tools. Compatible with analysis tools including
 * Lighthouse, IDA Pro, and Binary Ninja.
 * 
 * @return true if export completed successfully, false on error
 */
bool export_drcov_coverage() {
    auto* covered_addresses = get_covered_addresses();
    auto* address_sizes = get_address_sizes();
    
    if (covered_addresses->empty()) {
        if (g_debug_mode) {
            printf("[W1COV] No coverage data to export\n");
        }
        return false;
    }
    
    // Group collected addresses by their containing modules for DrCov format
    std::unordered_map<const QBDI::MemoryMap*, std::vector<std::pair<uint64_t, uint16_t>>> module_blocks;
    std::vector<const QBDI::MemoryMap*> module_list;
    
    for (const auto& addr : *covered_addresses) {
        const QBDI::MemoryMap* module = find_module_for_address(addr);
        if (module) {
            if (module_blocks.find(module) == module_blocks.end()) {
                module_list.push_back(module);
            }
            uint16_t size = address_sizes->count(addr) ? (*address_sizes)[addr] : 1;
            module_blocks[module].emplace_back(addr, size);
        }
    }
    
    if (module_blocks.empty()) {
        if (g_debug_mode) {
            printf("[W1COV] No coverage data mapped to modules\n");
        }
        return false;
    }
    
    try {
        // Use drcov library for consistent format writing
        auto builder = drcov::builder()
            .set_flavor("w1cov")
            .set_module_version(drcov::module_table_version::v2);
        
        // Add modules with sequential IDs
        for (const QBDI::MemoryMap* module : module_list) {
            std::string module_name = module->name.empty() ? "unknown" : module->name;
            builder.add_module(module_name, module->range.start(), module->range.end(), 0);
        }
        
        // Add basic blocks with actual instruction sizes
        uint16_t module_id = 0;
        for (const QBDI::MemoryMap* module : module_list) {
            const auto& blocks = module_blocks[module];
            for (const auto& block : blocks) {
                uint64_t addr = block.first;
                uint16_t size = block.second;
                uint32_t offset = static_cast<uint32_t>(addr - module->range.start());
                builder.add_coverage(module_id, offset, size);
            }
            module_id++;
        }
        
        // Build and write the coverage data
        auto coverage_data = builder.build();
        drcov::write(*get_output_file(), coverage_data);
        
        printf("[W1COV] Coverage exported: %zu addresses, %zu modules -> %s\n",
               covered_addresses->size(), module_blocks.size(), get_output_file()->c_str());
        
        return true;
        
    } catch (const std::exception& e) {
        printf("[W1COV] Failed to export coverage: %s\n", e.what());
        return false;
    }
}

} // namespace w1cov

// QBDIPreload callback implementations
extern "C" {

QBDIPRELOAD_INIT;

int qbdipreload_on_start(void *main) {
    // Always print something to verify library is loaded
    printf("[W1COV] qbdipreload_on_start called\n");
    fflush(stdout);
    
    printf("[W1COV] About to call configure_from_env()\n");
    fflush(stdout);
    w1cov::configure_from_env();
    printf("[W1COV] configure_from_env() completed\n");
    fflush(stdout);
    
    if (!w1cov::g_enabled) {
        printf("[W1COV] W1COV not enabled, exiting\n");
        fflush(stdout);
        return QBDIPRELOAD_NOT_HANDLED;
    }
    
    printf("[W1COV] W1COV enabled, continuing\n");
    fflush(stdout);
    
    printf("[W1COV] qbdipreload_on_start returning QBDIPRELOAD_NOT_HANDLED\n");
    fflush(stdout);
    return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_premain(void *gprCtx, void *fpuCtx) {
    return QBDIPRELOAD_NOT_HANDLED;
}

int qbdipreload_on_main(int argc, char **argv) {
    if (!w1cov::g_enabled) {
        return QBDIPRELOAD_NOT_HANDLED;
    }
    
    if (w1cov::g_debug_mode) {
        printf("[W1COV] qbdipreload_on_main: initializing module discovery\n");
    }
    
    // Discover modules early
    if (!w1cov::discover_modules()) {
        printf("[W1COV] Failed to discover modules\n");
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
        printf("[W1COV] qbdipreload_on_run: start=0x%llx, stop=0x%llx\n", start, stop);
    }
    
    // Register coverage callback (using same pattern as working tracer_preload.cpp)
    vm->addCodeCB(QBDI::PREINST, w1cov::coverage_callback, nullptr);
    
    if (w1cov::g_debug_mode) {
        printf("[W1COV] Coverage callback registered, starting instrumentation\n");
    }
    
    // Run with instrumentation
    vm->run(start, stop);
    
    if (w1cov::g_debug_mode) {
        printf("[W1COV] Instrumentation completed\n");
    }
    
    return QBDIPRELOAD_NO_ERROR;
}

int qbdipreload_on_exit(int status) {
    if (!w1cov::g_enabled) {
        return QBDIPRELOAD_NO_ERROR;
    }
    
    if (w1cov::g_debug_mode) {
        printf("[W1COV] qbdipreload_on_exit: exporting coverage data\n");
    }
    
    // Export coverage
    w1cov::export_drcov_coverage();
    
    if (w1cov::g_debug_mode) {
        printf("[W1COV] W1COV coverage collection completed\n");
    }
    
    return QBDIPRELOAD_NO_ERROR;
}

} // extern "C"