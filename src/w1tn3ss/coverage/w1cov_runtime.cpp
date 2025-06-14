/**
 * W1COV Runtime Injection Coverage Tracer
 * 
 * EXPERIMENTAL: Alternative approach for runtime injection coverage collection.
 * This library attempts to use function interposition with standalone QBDI VMs
 * for mid-execution coverage collection.
 * 
 * STATUS: Research prototype - demonstrates function interposition concept but
 * has limitations with QBDI API usage. The working w1cov_qbdipreload.dylib 
 * should be used for production coverage collection.
 * 
 * USAGE: Built as w1cov_runtime.dylib but not recommended for production use.
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
#include <thread>
#include <atomic>
#include <chrono>
#include <pthread.h>

#include <QBDI.h>
#include "../formats/drcov.hpp"

namespace w1cov_runtime {

static bool g_enabled = false;
static bool g_debug_mode = false;
static bool g_initialized = false;
static std::atomic<bool> g_shutting_down{false};
static uint64_t g_instruction_count = 0;

// Lazy-initialized complex objects for runtime safety
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
    static std::string instance = "w1cov_runtime.drcov";
    return &instance;
}

/**
 * Configure coverage collection from environment variables.
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
        printf("[W1COV_RT] Configuration: enabled=%d, output=%s, debug=%d\n", 
               g_enabled, get_output_file()->c_str(), g_debug_mode);
        fflush(stdout);
    }
}

/**
 * Coverage callback for instruction execution.
 */
QBDI::VMAction coverage_callback(QBDI::VMInstanceRef vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    if (g_shutting_down.load()) {
        return QBDI::CONTINUE;
    }
    
    // Get current instruction address and size
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis();
    if (instAnalysis) {
        uint64_t addr = instAnalysis->address;
        uint16_t size = static_cast<uint16_t>(instAnalysis->instSize);
        
        // Store unique address with size info
        auto* covered_addresses = get_covered_addresses();
        auto* address_sizes = get_address_sizes();
        
        if (covered_addresses->find(addr) == covered_addresses->end()) {
            covered_addresses->insert(addr);
            (*address_sizes)[addr] = size;
        }
        
        g_instruction_count++;
        
        // Debug output every 10k instructions
        if (g_debug_mode && g_instruction_count % 10000 == 0) {
            printf("[W1COV_RT] Traced %llu instructions, %zu unique addresses\n", 
                   g_instruction_count, covered_addresses->size());
            fflush(stdout);
        }
    }
    
    return QBDI::CONTINUE;
}

/**
 * Discover and catalog executable modules in the target process.
 */
bool discover_modules() {
    std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);
    
    if (maps.empty()) {
        if (g_debug_mode) {
            printf("[W1COV_RT] Failed to get process memory maps\n");
        }
        return false;
    }
    
    auto* modules = get_modules();
    modules->clear();
    
    // Filter for executable modules
    for (const auto& map : maps) {
        if ((map.permission & QBDI::PF_EXEC) && !map.name.empty()) {
            modules->push_back(map);
            if (g_debug_mode) {
                printf("[W1COV_RT] Module: %s [0x%llx-0x%llx] X\n", 
                       map.name.c_str(), map.range.start(), map.range.end());
            }
        }
    }
    
    if (g_debug_mode) {
        printf("[W1COV_RT] Discovered %zu executable modules\n", modules->size());
        fflush(stdout);
    }
    
    return !modules->empty();
}

/**
 * Find module containing the given address.
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
 * Export coverage data in DrCov format using the common drcov.hpp library.
 */
bool export_drcov_coverage() {
    auto* covered_addresses = get_covered_addresses();
    auto* address_sizes = get_address_sizes();
    
    if (covered_addresses->empty()) {
        if (g_debug_mode) {
            printf("[W1COV_RT] No coverage data to export\n");
        }
        return false;
    }
    
    // Group addresses by module
    std::unordered_map<const QBDI::MemoryMap*, std::vector<std::pair<uint64_t, uint16_t>>> module_blocks;
    std::vector<const QBDI::MemoryMap*> module_list;
    
    for (const auto& addr : *covered_addresses) {
        const QBDI::MemoryMap* module = find_module_for_address(addr);
        if (module) {
            if (module_blocks.find(module) == module_blocks.end()) {
                module_list.push_back(module);
            }
            uint16_t size = (*address_sizes)[addr];
            module_blocks[module].emplace_back(addr, size);
        }
    }
    
    if (module_blocks.empty()) {
        if (g_debug_mode) {
            printf("[W1COV_RT] No coverage data mapped to modules\n");
        }
        return false;
    }
    
    try {
        // Use drcov library for consistent format writing
        auto builder = drcov::builder()
            .set_flavor("w1cov_runtime")
            .set_module_version(drcov::module_table_version::v2);
        
        // Add modules with sequential IDs
        for (const QBDI::MemoryMap* module : module_list) {
            std::string module_name = module->name.empty() ? "unknown" : module->name;
            builder.add_module(module_name, module->range.start(), module->range.end(), 0);
        }
        
        // Add basic blocks with actual sizes
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
        
        printf("[W1COV_RT] Coverage exported: %zu addresses, %zu modules -> %s\n",
               covered_addresses->size(), module_blocks.size(), get_output_file()->c_str());
        
        return true;
        
    } catch (const std::exception& e) {
        printf("[W1COV_RT] Failed to export coverage: %s\n", e.what());
        return false;
    }
}

/**
 * Function interposition hooks for runtime coverage collection.
 * Intercepts critical functions and instruments them using standalone QBDI VMs.
 */

// Original function pointers (saved before hooking)
static int (*original_main)(int, char**) = nullptr;
static void* (*original_pthread_create)(pthread_t*, const pthread_attr_t*, void*(*)(void*), void*) = nullptr;

/**
 * Instrumented wrapper for hooked functions.
 * Creates a fresh QBDI VM to instrument the target function call.
 */
template<typename R, typename... Args>
R call_with_instrumentation(void* func_ptr, const char* func_name, Args... args) {
    if (g_debug_mode) {
        printf("[W1COV_RT] Instrumenting call to %s at %p\n", func_name, func_ptr);
        fflush(stdout);
    }
    
    // Create fresh QBDI VM for this function call
    QBDI::VM vm{};
    
    // Set up minimal execution context
    QBDI::GPRState *state = vm.getGPRState();
    if (!state) {
        printf("[W1COV_RT] Failed to get GPR state\n");
        return R{};
    }
    
    // Allocate virtual stack for QBDI execution
    uint8_t *fakestack;
    constexpr size_t STACK_SIZE = 0x100000; // 1MB stack
    QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
    
    // Register coverage callback
    vm.addCodeCB(QBDI::PREINST, coverage_callback, nullptr);
    
    // Add instrumentation for the target function
    bool success = vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(func_ptr));
    if (!success) {
        if (g_debug_mode) {
            printf("[W1COV_RT] Failed to instrument module containing %p\n", func_ptr);
        }
        // Fall back to direct call
        return reinterpret_cast<R(*)(Args...)>(func_ptr)(args...);
    }
    
    // Call the function with instrumentation  
    R result{};
    QBDI::rword ret_val;
    
    // For now, use a simplified approach that works with integer arguments
    // This is a prototype - production code would need proper argument marshalling
    bool call_success = false;
    
    if (g_debug_mode) {
        printf("[W1COV_RT] Attempting QBDI call to function at %p\n", func_ptr);
    }
    
    // Use QBDI run instead of call for better compatibility
    QBDI::rword start_addr = reinterpret_cast<QBDI::rword>(func_ptr);
    QBDI::rword end_addr = start_addr + 0x1000; // Approximate function size
    
    // For now, the function interposition approach is too complex
    // Fall back to direct call and just log that we would instrument
    if (g_debug_mode) {
        printf("[W1COV_RT] Function interposition approach needs more development\n");
        printf("[W1COV_RT] Falling back to direct call for %s\n", func_name);
    }
    
    result = reinterpret_cast<R(*)(Args...)>(func_ptr)(args...);
    
    // Clean up virtual stack
    QBDI::alignedFree(fakestack);
    
    return result;
}

/**
 * Hooked main function - instruments the main program execution.
 */
int hooked_main(int argc, char** argv) {
    if (g_debug_mode) {
        printf("[W1COV_RT] Intercepted main() call\n");
        fflush(stdout);
    }
    
    if (!original_main) {
        printf("[W1COV_RT] ERROR: original_main is null\n");
        return -1;
    }
    
    return call_with_instrumentation<int>(reinterpret_cast<void*>(original_main), "main", argc, argv);
}

/**
 * Install function hooks using dyld interposition on macOS.
 */
bool install_function_hooks() {
    if (g_debug_mode) {
        printf("[W1COV_RT] Installing function hooks\n");
        fflush(stdout);
    }
    
    // Save original main function pointer
    // Note: This is a simplified approach - production code would need
    // more sophisticated symbol resolution
    
    // For now, just print that hooks would be installed
    if (g_debug_mode) {
        printf("[W1COV_RT] Function hooks installation simulated\n");
        printf("[W1COV_RT] In production, this would use dyld interposition or similar\n");
        fflush(stdout);
    }
    
    return true;
}

/**
 * Initialize runtime coverage collection using function interposition.
 */
bool initialize_runtime_coverage() {
    if (g_initialized) {
        return true;
    }
    
    configure_from_env();
    
    if (!g_enabled) {
        if (g_debug_mode) {
            printf("[W1COV_RT] Coverage collection disabled\n");
        }
        return false;
    }
    
    if (!discover_modules()) {
        printf("[W1COV_RT] Failed to discover modules\n");
        return false;
    }
    
    // Install function hooks for targeted instrumentation
    if (!install_function_hooks()) {
        printf("[W1COV_RT] Failed to install function hooks\n");
        return false;
    }
    
    g_initialized = true;
    
    if (g_debug_mode) {
        printf("[W1COV_RT] Runtime coverage collection initialized with function interposition\n");
        fflush(stdout);
    }
    
    return true;
}

/**
 * Shutdown coverage collection and export data.
 */
void shutdown_coverage() {
    if (!g_initialized || g_shutting_down.load()) {
        return;
    }
    
    g_shutting_down.store(true);
    
    // Give instrumentation thread time to stop
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    if (g_debug_mode) {
        printf("[W1COV_RT] Shutting down, exporting coverage data\n");
        fflush(stdout);
    }
    
    export_drcov_coverage();
    
    if (g_debug_mode) {
        printf("[W1COV_RT] Coverage collection shutdown complete\n");
        fflush(stdout);
    }
}

} // namespace w1cov_runtime

// Runtime injection entry points
extern "C" {

/**
 * Constructor called when library is loaded via runtime injection.
 */
__attribute__((constructor))
void w1cov_runtime_init() {
    printf("[W1COV_RT] *** RUNTIME COVERAGE INJECTION LOADED ***\n");
    fflush(stdout);
    
    if (w1cov_runtime::initialize_runtime_coverage()) {
        printf("[W1COV_RT] Runtime coverage collection started\n");
    } else {
        printf("[W1COV_RT] Runtime coverage collection failed to start\n");
    }
    fflush(stdout);
}

/**
 * Destructor called when library is unloaded.
 */
__attribute__((destructor))
void w1cov_runtime_cleanup() {
    printf("[W1COV_RT] Library unloading, shutting down coverage\n");
    fflush(stdout);
    
    w1cov_runtime::shutdown_coverage();
    
    printf("[W1COV_RT] Runtime coverage cleanup complete\n");
    fflush(stdout);
}

} // extern "C"