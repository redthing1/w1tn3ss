/**
 * W1COV Sampling-Based Runtime Coverage Tracer
 * 
 * EXPERIMENTAL: Lightweight alternative for runtime coverage collection using 
 * signal-based PC sampling instead of full QBDI instrumentation.
 * 
 * CONCEPT: Captures program counter at regular intervals (1000Hz) to provide
 * lower-overhead coverage approximation suitable for runtime scenarios.
 * 
 * STATUS: Research prototype - signal handling needs refinement for production use.
 * The working w1cov_qbdipreload.dylib provides comprehensive coverage and should 
 * be used for accurate analysis.
 * 
 * USAGE: Built as w1cov_sampling.dylib for research purposes.
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
#include <signal.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include <QBDI.h>

namespace w1cov_sampling {

static bool g_enabled = false;
static bool g_debug_mode = false;
static bool g_initialized = false;
static std::atomic<bool> g_running{false};
static std::atomic<uint64_t> g_sample_count{0};

// Lazy-initialized containers
static std::unordered_set<uint64_t>* get_sampled_addresses() {
    static std::unordered_set<uint64_t> instance;
    return &instance;
}

static std::vector<QBDI::MemoryMap>* get_modules() {
    static std::vector<QBDI::MemoryMap> instance;
    return &instance;
}

static std::string* get_output_file() {
    static std::string instance = "w1cov_sampling.drcov";
    return &instance;
}

/**
 * Configure from environment variables.
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
}

/**
 * Discover executable modules.
 */
bool discover_modules() {
    std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);
    
    if (maps.empty()) {
        return false;
    }
    
    auto* modules = get_modules();
    modules->clear();
    
    for (const auto& map : maps) {
        if ((map.permission & QBDI::PF_EXEC) && !map.name.empty()) {
            modules->push_back(map);
            if (g_debug_mode) {
                printf("[W1COV_SAMP] Module: %s [0x%llx-0x%llx]\n", 
                       map.name.c_str(), map.range.start(), map.range.end());
            }
        }
    }
    
    return !modules->empty();
}

/**
 * Find module containing address.
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
 * Signal handler for sampling-based coverage collection.
 * Captures program counter at regular intervals.
 */
void sampling_signal_handler(int sig, siginfo_t* info, void* context) {
    if (!g_running.load()) {
        return;
    }
    
    // Extract program counter from signal context
    ucontext_t* uctx = static_cast<ucontext_t*>(context);
    uint64_t pc = 0;
    
#ifdef __x86_64__
    pc = uctx->uc_mcontext->__ss.__rip;
#elif defined(__aarch64__) || defined(__arm64__)
    pc = uctx->uc_mcontext->__ss.__pc;
#endif
    
    if (pc != 0) {
        // Check if PC is in an executable module
        const QBDI::MemoryMap* module = find_module_for_address(pc);
        if (module) {
            get_sampled_addresses()->insert(pc);
            g_sample_count.fetch_add(1);
            
            if (g_debug_mode && g_sample_count.load() % 1000 == 0) {
                printf("[W1COV_SAMP] Collected %llu samples, %zu unique addresses\n",
                       g_sample_count.load(), get_sampled_addresses()->size());
            }
        }
    }
}

/**
 * Sampling thread that generates periodic signals for PC sampling.
 */
void* sampling_thread(void* arg) {
    if (g_debug_mode) {
        printf("[W1COV_SAMP] Sampling thread started\n");
        fflush(stdout);
    }
    
    // Sample at ~1000 Hz
    const auto sample_interval = std::chrono::microseconds(1000);
    
    while (g_running.load()) {
        // Send SIGALRM to main thread for PC sampling
        pthread_kill(pthread_self(), SIGALRM);
        
        std::this_thread::sleep_for(sample_interval);
    }
    
    if (g_debug_mode) {
        printf("[W1COV_SAMP] Sampling thread stopped\n");
        fflush(stdout);
    }
    
    return nullptr;
}

/**
 * Export coverage data in DrCov format.
 */
bool export_drcov_coverage() {
    auto* sampled_addresses = get_sampled_addresses();
    
    if (sampled_addresses->empty()) {
        if (g_debug_mode) {
            printf("[W1COV_SAMP] No coverage data to export\n");
        }
        return false;
    }
    
    // Group addresses by module
    std::unordered_map<const QBDI::MemoryMap*, std::vector<uint64_t>> module_blocks;
    std::vector<const QBDI::MemoryMap*> module_list;
    
    for (const auto& addr : *sampled_addresses) {
        const QBDI::MemoryMap* module = find_module_for_address(addr);
        if (module) {
            if (module_blocks.find(module) == module_blocks.end()) {
                module_list.push_back(module);
            }
            module_blocks[module].push_back(addr);
        }
    }
    
    // Write DrCov file
    std::ofstream fp(*get_output_file());
    if (!fp.is_open()) {
        printf("[W1COV_SAMP] Failed to open output file: %s\n", get_output_file()->c_str());
        return false;
    }
    
    fp << "DRCOV VERSION: 2\n";
    fp << "DRCOV FLAVOR: drcov\n";
    fp << "Module Table: version 2, count " << module_list.size() << "\n";
    fp << "Columns: id, base, end, entry, path\n";
    
    uint16_t module_id = 0;
    for (const QBDI::MemoryMap* module : module_list) {
        fp << std::setw(2) << module_id << ", "
           << "0x" << std::hex << module->range.start() << ", "
           << "0x" << std::hex << module->range.end() << ", "
           << "0x" << std::setfill('0') << std::setw(16) << "0" << ", "
           << (module->name.empty() ? "unknown" : module->name) << "\n";
        module_id++;
    }
    
    // Count total blocks
    size_t total_blocks = 0;
    for (const auto& pair : module_blocks) {
        total_blocks += pair.second.size();
    }
    
    fp << "BB Table: " << total_blocks << " bbs\n";
    fp.close();
    
    // Write binary block data
    std::ofstream fp_bin(*get_output_file(), std::ios::binary | std::ios::app);
    if (!fp_bin.is_open()) {
        printf("[W1COV_SAMP] Failed to open output file for binary write: %s\n", get_output_file()->c_str());
        return false;
    }
    
    module_id = 0;
    for (const QBDI::MemoryMap* module : module_list) {
        const auto& blocks = module_blocks[module];
        for (const auto& addr : blocks) {
            uint32_t offset = static_cast<uint32_t>(addr - module->range.start());
            uint16_t size = 1; // Sampling doesn't give us instruction sizes
            
            // DrCov binary format: uint32_t start; uint16_t size; uint16_t id;
            fp_bin.write(reinterpret_cast<const char*>(&offset), sizeof(uint32_t));
            fp_bin.write(reinterpret_cast<const char*>(&size), sizeof(uint16_t));
            fp_bin.write(reinterpret_cast<const char*>(&module_id), sizeof(uint16_t));
        }
        module_id++;
    }
    
    fp_bin.close();
    
    printf("[W1COV_SAMP] Sampling coverage exported: %zu addresses, %zu modules -> %s\n",
           sampled_addresses->size(), module_blocks.size(), get_output_file()->c_str());
    
    return true;
}

/**
 * Initialize sampling-based coverage collection.
 */
bool initialize_sampling_coverage() {
    if (g_initialized) {
        return true;
    }
    
    configure_from_env();
    
    if (!g_enabled) {
        if (g_debug_mode) {
            printf("[W1COV_SAMP] Coverage collection disabled\n");
        }
        return false;
    }
    
    if (!discover_modules()) {
        printf("[W1COV_SAMP] Failed to discover modules\n");
        return false;
    }
    
    // Install signal handler for sampling
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sampling_signal_handler;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGALRM, &sa, nullptr) == -1) {
        printf("[W1COV_SAMP] Failed to install signal handler\n");
        return false;
    }
    
    g_running.store(true);
    
    // Start sampling thread
    pthread_t thread;
    int ret = pthread_create(&thread, nullptr, sampling_thread, nullptr);
    if (ret != 0) {
        printf("[W1COV_SAMP] Failed to create sampling thread\n");
        g_running.store(false);
        return false;
    }
    
    pthread_detach(thread);
    
    g_initialized = true;
    
    if (g_debug_mode) {
        printf("[W1COV_SAMP] Sampling coverage collection initialized\n");
        fflush(stdout);
    }
    
    return true;
}

/**
 * Shutdown sampling coverage collection.
 */
void shutdown_sampling_coverage() {
    if (!g_initialized || !g_running.load()) {
        return;
    }
    
    g_running.store(false);
    
    // Give sampling thread time to stop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    if (g_debug_mode) {
        printf("[W1COV_SAMP] Shutting down, exporting coverage data\n");
        fflush(stdout);
    }
    
    export_drcov_coverage();
    
    if (g_debug_mode) {
        printf("[W1COV_SAMP] Sampling coverage collection shutdown complete\n");
        fflush(stdout);
    }
}

} // namespace w1cov_sampling

// Runtime injection entry points
extern "C" {

/**
 * Constructor called when library is loaded via runtime injection.
 */
__attribute__((constructor))
void w1cov_sampling_init() {
    printf("[W1COV_SAMP] *** SAMPLING COVERAGE INJECTION LOADED ***\n");
    fflush(stdout);
    
    if (w1cov_sampling::initialize_sampling_coverage()) {
        printf("[W1COV_SAMP] Sampling coverage collection started\n");
    } else {
        printf("[W1COV_SAMP] Sampling coverage collection failed to start\n");
    }
    fflush(stdout);
}

/**
 * Destructor called when library is unloaded.
 */
__attribute__((destructor))
void w1cov_sampling_cleanup() {
    printf("[W1COV_SAMP] Library unloading, shutting down coverage\n");
    fflush(stdout);
    
    w1cov_sampling::shutdown_sampling_coverage();
    
    printf("[W1COV_SAMP] Sampling coverage cleanup complete\n");
    fflush(stdout);
}

} // extern "C"