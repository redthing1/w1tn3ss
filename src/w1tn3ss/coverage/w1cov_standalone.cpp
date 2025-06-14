#include "w1cov_standalone.hpp"
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <QBDI.h>
#include <redlog/redlog.hpp>
#include "coverage_data.hpp"
#include "module_mapper.hpp"

namespace w1::coverage {

class w1cov_standalone::impl {
public:
    redlog::logger log;
    std::unique_ptr<coverage_collector> collector;
    std::unique_ptr<module_mapper> mapper;
    std::unordered_set<uint64_t> covered_addresses;
    std::unordered_map<uint64_t, std::string> address_modules;
    
    bool initialized;
    
    impl() : log(redlog::get_logger("w1tn3ss.w1cov_standalone")),
             initialized(false) {
        log.info("w1cov standalone implementation created");
    }
    
    ~impl() {
        cleanup();
    }
    
    void cleanup() {
        mapper.reset();
        collector.reset();
    }
};

// Coverage callback - simple and reliable
static QBDI::VMAction coverage_callback(QBDI::VM *vm, QBDI::GPRState *gprState,
                                        QBDI::FPRState *fprState, void *data) {
    auto* cov_impl = static_cast<w1cov_standalone::impl*>(data);
    
    // Get instruction analysis and track unique addresses only
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis();
    if (instAnalysis) {
        cov_impl->covered_addresses.insert(instAnalysis->address);
        // Note: collector integration happens post-execution to avoid callback issues
    }
    
    return QBDI::VMAction::CONTINUE;
}

w1cov_standalone::w1cov_standalone() : pimpl(std::make_unique<impl>()) {}

w1cov_standalone::~w1cov_standalone() = default;

bool w1cov_standalone::initialize() {
    if (pimpl->initialized) {
        pimpl->log.warn("already initialized");
        return true;
    }
    
    pimpl->log.info("initializing w1cov standalone");
    
    try {
        // Create components - no VM setup needed since we create fresh VMs per call
        pimpl->collector = std::make_unique<coverage_collector>();
        pimpl->mapper = std::make_unique<module_mapper>(*pimpl->collector);
        
        pimpl->initialized = true;
        pimpl->log.info("w1cov standalone initialized successfully");
        return true;
        
    } catch (const std::exception& e) {
        pimpl->log.error("initialization failed", redlog::field("error", e.what()));
        return false;
    }
}

bool w1cov_standalone::instrument_function(void* func_ptr, const std::string& name) {
    if (!pimpl->initialized) {
        pimpl->log.error("not initialized");
        return false;
    }
    
    pimpl->log.info("marking function for instrumentation", 
                   redlog::field("name", name),
                   redlog::field("address", reinterpret_cast<uint64_t>(func_ptr)));
    
    // In our new approach, we don't pre-instrument functions
    // Instead, each call creates a fresh VM and instruments on-demand
    // This just validates the function pointer is reasonable
    
    if (!func_ptr) {
        pimpl->log.error("invalid function pointer", redlog::field("function", name));
        return false;
    }
    
    pimpl->log.info("function ready for instrumentation", redlog::field("name", name));
    return true;
}

bool w1cov_standalone::call_instrumented_function(void* func_ptr, 
                                                  const std::vector<uint64_t>& args,
                                                  uint64_t* result) {
    if (!pimpl->initialized) {
        pimpl->log.error("not initialized");
        return false;
    }
    
    pimpl->log.info("calling instrumented function", 
                   redlog::field("address", reinterpret_cast<uint64_t>(func_ptr)),
                   redlog::field("arg_count", args.size()));
    
    try {
        // Create fresh VM for each call - working pattern
        QBDI::VM vm{};
        
        // Get a pointer to the GPR state of the VM
        QBDI::GPRState *state = vm.getGPRState();
        if (!state) {
            pimpl->log.error("failed to get GPR state");
            return false;
        }
        
        // Setup virtual stack
        uint8_t *fakestack;
        static const size_t STACK_SIZE = 0x100000; // 1MB
        bool res = QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
        if (!res) {
            pimpl->log.error("failed to allocate virtual stack");
            return false;
        }
        
        // Register coverage callback
        uint32_t cid = vm.addCodeCB(QBDI::PREINST, coverage_callback, pimpl.get());
        if (cid == QBDI::INVALID_EVENTID) {
            pimpl->log.error("failed to register coverage callback");
            QBDI::alignedFree(fakestack);
            return false;
        }
        
        // Setup Instrumentation Range
        res = vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(func_ptr));
        if (!res) {
            pimpl->log.error("failed to add instrumentation range");
            QBDI::alignedFree(fakestack);
            return false;
        }
        
        // Call function with QBDI
        QBDI::rword retvalue;
        if (args.empty()) {
            res = vm.call(&retvalue, reinterpret_cast<QBDI::rword>(func_ptr));
        } else {
            // Convert all arguments
            std::vector<QBDI::rword> qbdi_args;
            for (uint64_t arg : args) {
                qbdi_args.push_back(static_cast<QBDI::rword>(arg));
            }
            res = vm.call(&retvalue, reinterpret_cast<QBDI::rword>(func_ptr), qbdi_args);
        }
        
        // Cleanup stack
        QBDI::alignedFree(fakestack);
        
        if (!res) {
            pimpl->log.error("QBDI call failed");
            return false;
        }
        
        if (result) {
            *result = static_cast<uint64_t>(retvalue);
        }
        
        // Note: Basic block recording happens during export to avoid initialization issues
        
        pimpl->log.info("instrumented function call completed", 
                       redlog::field("return_value", retvalue),
                       redlog::field("addresses_covered", pimpl->covered_addresses.size()));
        
        return true;
        
    } catch (const std::exception& e) {
        pimpl->log.error("call failed", redlog::field("error", e.what()));
        return false;
    }
}

size_t w1cov_standalone::get_coverage_count() const {
    return pimpl->covered_addresses.size();
}

bool w1cov_standalone::run_instrumented_binary(const std::string& binary_path,
                                               const std::vector<std::string>& args,
                                               int* exit_code) {
    if (!pimpl->initialized) {
        pimpl->log.error("not initialized");
        return false;
    }
    
    pimpl->log.info("running instrumented binary", 
                   redlog::field("binary_path", binary_path),
                   redlog::field("arg_count", args.size()));
    
    try {
        // Create fresh VM for binary execution - working pattern
        QBDI::VM vm{};
        
        // Get a pointer to the GPR state of the VM
        QBDI::GPRState *state = vm.getGPRState();
        if (!state) {
            pimpl->log.error("failed to get GPR state");
            return false;
        }
        
        // Setup virtual stack
        uint8_t *fakestack;
        static const size_t STACK_SIZE = 0x100000; // 1MB
        bool res = QBDI::allocateVirtualStack(state, STACK_SIZE, &fakestack);
        if (!res) {
            pimpl->log.error("failed to allocate virtual stack");
            return false;
        }
        
        // Register coverage callback
        uint32_t cid = vm.addCodeCB(QBDI::PREINST, coverage_callback, pimpl.get());
        if (cid == QBDI::INVALID_EVENTID) {
            pimpl->log.error("failed to register coverage callback");
            QBDI::alignedFree(fakestack);
            return false;
        }
        
        // For binary instrumentation, we need to load the binary and get its entry point
        // This is a simplified approach - in practice, we'd use proper ELF/Mach-O parsing
        pimpl->log.info("attempting to load binary for instrumentation");
        
        // Try to instrument all executable memory for comprehensive coverage
        res = vm.instrumentAllExecutableMaps();
        if (!res) {
            pimpl->log.warn("failed to instrument all executable maps, trying specific module");
            // Fallback: try to load and instrument the specific binary
            // This would require proper binary loading which is complex
            QBDI::alignedFree(fakestack);
            return false;
        }
        
        // Set up fake return address for run() method
        const QBDI::rword FAKE_RET_ADDR = 0x40000;
        
        // Use w1nj3ct to launch binary with w1cov library injected
        // This leverages the existing injection infrastructure
        pimpl->log.info("using w1nj3ct for binary launching with coverage injection");
        
        // For now, this is a placeholder - the actual implementation should:
        // 1. Build w1cov as a dynamic library (.dylib/.so/.dll)
        // 2. Use w1nj3ct::inject_library_launch to spawn the binary with w1cov injected
        // 3. The injected w1cov library would automatically start coverage collection
        // 4. Communication between the launcher and injected library via shared files/IPC
        
        pimpl->log.warn("binary launching via injection requires w1cov to be built as a dynamic library");
        pimpl->log.info("use w1tool inject -t w1cov -L ./w1cov.dylib -b ./target instead");
        
        QBDI::alignedFree(fakestack);
        return false;
        
    } catch (const std::exception& e) {
        pimpl->log.error("binary instrumentation failed", redlog::field("error", e.what()));
        return false;
    }
}

bool w1cov_standalone::export_coverage(const std::string& output_file) {
    if (!pimpl->collector) {
        pimpl->log.error("collector not initialized");
        return false;
    }
    
    pimpl->log.info("exporting coverage data", redlog::field("output_file", output_file));
    
    // If we have collected addresses but no modules, create a temporary module for export
    if (pimpl->covered_addresses.size() > 0) {
        // Find address range
        uint64_t min_addr = *std::min_element(pimpl->covered_addresses.begin(), pimpl->covered_addresses.end());
        uint64_t max_addr = *std::max_element(pimpl->covered_addresses.begin(), pimpl->covered_addresses.end());
        
        // Align to page boundaries for module range
        uint64_t module_base = min_addr & ~0xFFF;  // page-align down
        uint64_t module_end = (max_addr + 0xFFF) & ~0xFFF;  // page-align up
        
        // Add a temporary module covering our addresses
        uint16_t module_id = pimpl->collector->add_module("instrumented_code", module_base, module_end, module_base);
        
        if (module_id != UINT16_MAX) {
            // Record all our addresses as basic blocks
            for (uint64_t addr : pimpl->covered_addresses) {
                try {
                    pimpl->collector->record_basic_block_with_module(addr, 4, module_id);  // 4-byte ARM64 instructions
                } catch (const std::exception& e) {
                    pimpl->log.debug("failed to record address for export", 
                                   redlog::field("address", addr),
                                   redlog::field("error", e.what()));
                }
            }
            
            pimpl->log.info("created temporary module for export",
                           redlog::field("module_id", module_id),
                           redlog::field("base", module_base),
                           redlog::field("end", module_end),
                           redlog::field("addresses", pimpl->covered_addresses.size()));
        }
    }
    
    // Set output file and export
    pimpl->collector->set_output_file(output_file);
    bool success = pimpl->collector->write_drcov_file(output_file);
    
    if (success) {
        pimpl->log.info("coverage export successful", 
                       redlog::field("output_file", output_file),
                       redlog::field("unique_addresses", pimpl->covered_addresses.size()));
    } else {
        pimpl->log.error("coverage export failed", redlog::field("output_file", output_file));
    }
    
    return success;
}

void w1cov_standalone::print_stats() const {
    pimpl->log.info("coverage statistics",
                   redlog::field("unique_addresses", pimpl->covered_addresses.size()),
                   redlog::field("total_blocks", pimpl->collector ? pimpl->collector->get_total_blocks() : 0));
}

} // namespace w1::coverage