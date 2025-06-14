#include "w1cov_tracer.hpp"
#include "coverage_data.hpp"
#include "module_mapper.hpp"
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <sstream>

// qbdi includes
#include <QBDI.h>

namespace w1::coverage {

w1cov_tracer::w1cov_tracer()
    : log_(redlog::get_logger("w1tn3ss.w1cov")),
      initialized_(false),
      instrumenting_(false),
      qbdi_vm_(nullptr),
      output_file_("coverage.drcov"),
      exclude_system_(true) {
    log_.debug("w1cov tracer created");
}

w1cov_tracer::~w1cov_tracer() {
    if (is_instrumenting()) {
        stop_instrumentation();
    }
    
    if (is_initialized()) {
        shutdown();
    }
    
    log_.debug("w1cov tracer destroyed");
}

bool w1cov_tracer::initialize() {
    if (initialized_) {
        log_.warn("tracer already initialized");
        return true;
    }
    
    log_.info("initializing w1cov tracer");
    
    try {
        // create core components
        collector_ = std::make_unique<coverage_collector>();
        mapper_ = std::make_unique<module_mapper>(*collector_);
        
        // configure from environment
        configure_from_environment();
        
        // setup qbdi vm
        if (!setup_qbdi_vm()) {
            log_.error("failed to setup qbdi vm");
            return false;
        }
        
        initialized_ = true;
        log_.info("w1cov tracer initialized successfully");
        return true;
        
    } catch (const std::exception& e) {
        log_.error("initialization failed", redlog::field("error", e.what()));
        return false;
    }
}

void w1cov_tracer::shutdown() {
    if (!initialized_) {
        return;
    }
    
    log_.info("shutting down w1cov tracer");
    
    // stop instrumentation if running
    if (is_instrumenting()) {
        stop_instrumentation();
    }
    
    // export final coverage data
    export_coverage_data();
    
    // cleanup qbdi
    cleanup_qbdi_vm();
    
    // cleanup components
    mapper_.reset();
    collector_.reset();
    
    initialized_ = false;
    log_.info("w1cov tracer shutdown complete");
}

void w1cov_tracer::configure_from_environment() {
    log_.debug("configuring from environment variables");
    
    // check if w1cov is enabled
    if (!get_env_bool("W1COV_ENABLED", false)) {
        log_.info("w1cov not enabled via environment");
        return;
    }
    
    // get output file
    output_file_ = get_env_var("W1COV_OUTPUT_FILE", "coverage.drcov");
    log_.info("output file configured", redlog::field("file", output_file_));
    
    // get system module exclusion setting
    exclude_system_ = get_env_bool("W1COV_EXCLUDE_SYSTEM", true);
    log_.info("system module exclusion configured", redlog::field("exclude", exclude_system_));
    
    // configure components
    if (collector_) {
        collector_->set_exclude_system_modules(exclude_system_);
        collector_->set_output_file(output_file_);
    }
    
    if (mapper_) {
        mapper_->set_exclude_system_modules(exclude_system_);
    }
    
    // get target module patterns
    std::string target_modules = get_env_var("W1COV_TARGET_MODULES", "");
    if (!target_modules.empty()) {
        // split comma-separated patterns
        std::stringstream ss(target_modules);
        std::string pattern;
        while (std::getline(ss, pattern, ',')) {
            if (!pattern.empty() && mapper_) {
                mapper_->add_target_module_pattern(pattern);
                log_.info("added target module pattern", redlog::field("pattern", pattern));
            }
        }
    }
}

void w1cov_tracer::set_output_file(const std::string& filepath) {
    output_file_ = filepath;
    if (collector_) {
        collector_->set_output_file(filepath);
    }
}

void w1cov_tracer::set_exclude_system_modules(bool exclude) {
    exclude_system_ = exclude;
    if (collector_) {
        collector_->set_exclude_system_modules(exclude);
    }
    if (mapper_) {
        mapper_->set_exclude_system_modules(exclude);
    }
}

void w1cov_tracer::add_target_module_pattern(const std::string& pattern) {
    if (mapper_) {
        mapper_->add_target_module_pattern(pattern);
    }
}

bool w1cov_tracer::start_instrumentation() {
    if (!initialized_) {
        log_.error("tracer not initialized");
        return false;
    }
    
    if (instrumenting_) {
        log_.warn("instrumentation already running");
        return true;
    }
    
    log_.info("starting coverage instrumentation");
    
    try {
        // discover and register modules
        if (!discover_and_register_modules()) {
            log_.error("failed to discover modules");
            return false;
        }
        
        // setup instrumentation ranges
        if (!setup_instrumentation_ranges()) {
            log_.error("failed to setup instrumentation ranges");
            return false;
        }
        
        // register callbacks
        if (!register_callbacks()) {
            log_.error("failed to register callbacks");
            return false;
        }
        
        instrumenting_ = true;
        log_.info("coverage instrumentation started successfully");
        return true;
        
    } catch (const std::exception& e) {
        log_.error("failed to start instrumentation", redlog::field("error", e.what()));
        return false;
    }
}

bool w1cov_tracer::stop_instrumentation() {
    if (!instrumenting_) {
        return true;
    }
    
    log_.info("stopping coverage instrumentation");
    
    try {
        // qbdi cleanup is handled in cleanup_qbdi_vm()
        instrumenting_ = false;
        
        // print final statistics
        print_statistics();
        
        log_.info("coverage instrumentation stopped");
        return true;
        
    } catch (const std::exception& e) {
        log_.error("error stopping instrumentation", redlog::field("error", e.what()));
        return false;
    }
}

bool w1cov_tracer::setup_qbdi_vm() {
    log_.debug("setting up qbdi vm");
    
    try {
        auto* vm = new QBDI::VM();
        qbdi_vm_ = static_cast<QBDIVMPtr>(vm);
        
        // get vm state
        QBDI::GPRState* gprState = vm->getGPRState();
        if (!gprState) {
            log_.error("failed to get gpr state from qbdi vm");
            return false;
        }
        
        // allocate virtual stack
        uint8_t* fakestack = nullptr;
        constexpr size_t STACK_SIZE = 0x100000; // 1MB stack
        bool success = QBDI::allocateVirtualStack(gprState, STACK_SIZE, &fakestack);
        if (!success) {
            log_.error("failed to allocate virtual stack");
            return false;
        }
        
        log_.debug("qbdi vm setup completed",
                   redlog::field("stack_size", STACK_SIZE));
        
        return true;
        
    } catch (const std::exception& e) {
        log_.error("qbdi vm setup failed", redlog::field("error", e.what()));
        return false;
    }
}

bool w1cov_tracer::register_callbacks() {
    if (!qbdi_vm_) {
        log_.error("qbdi vm not initialized");
        return false;
    }
    
    log_.debug("registering qbdi callbacks");
    
    try {
        auto* vm = static_cast<QBDI::VM*>(qbdi_vm_);
        
        // register basic block callback
        uint32_t bb_cb_id = vm->addVMEventCB(
            QBDI::VMEvent::BASIC_BLOCK_ENTRY,
            reinterpret_cast<QBDI::VMCallback>(basic_block_callback),
            this
        );
        
        if (bb_cb_id == QBDI::INVALID_EVENTID) {
            log_.error("failed to register basic block callback");
            return false;
        }
        
        log_.debug("registered basic block callback", redlog::field("id", bb_cb_id));
        
        // optionally register instruction callback for more detailed tracing
        if (redlog::get_level() <= redlog::level::trace) {
            uint32_t inst_cb_id = vm->addCodeCB(
                QBDI::PREINST,
                reinterpret_cast<QBDI::InstCallback>(instruction_callback),
                this
            );
            
            if (inst_cb_id != QBDI::INVALID_EVENTID) {
                log_.trace("registered instruction callback", redlog::field("id", inst_cb_id));
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        log_.error("callback registration failed", redlog::field("error", e.what()));
        return false;
    }
}

void w1cov_tracer::cleanup_qbdi_vm() {
    if (qbdi_vm_) {
        log_.debug("cleaning up qbdi vm");
        
        // delete the QBDI VM instance
        delete static_cast<QBDI::VM*>(qbdi_vm_);
        qbdi_vm_ = nullptr;
    }
}

QBDIVMAction w1cov_tracer::basic_block_callback(
    QBDIVMPtr vm,
    QBDIVMStatePtr vmState,
    QBDIGPRStatePtr gprState,
    QBDIFPRStatePtr fprState,
    void* data) {
    
    auto* tracer = static_cast<w1cov_tracer*>(data);
    if (!tracer || !vmState) {
        return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
    }
    
    try {
        // cast back to QBDI types
        const QBDI::VMState* state = static_cast<const QBDI::VMState*>(vmState);
        
        // get basic block info
        uint64_t bb_start = state->basicBlockStart;
        uint16_t bb_size = static_cast<uint16_t>(state->basicBlockEnd - state->basicBlockStart);
        
        tracer->handle_basic_block_entry(bb_start, bb_size);
        
    } catch (const std::exception& e) {
        tracer->log_.error("error in basic block callback", redlog::field("error", e.what()));
    }
    
    return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
}

QBDIVMAction w1cov_tracer::instruction_callback(
    QBDIVMPtr vm,
    QBDIGPRStatePtr gprState,
    QBDIFPRStatePtr fprState,
    void* data) {
    
    auto* tracer = static_cast<w1cov_tracer*>(data);
    if (!tracer || !vm) {
        return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
    }
    
    try {
        QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
        const QBDI::InstAnalysis* analysis = qbdi_vm->getInstAnalysis();
        if (analysis) {
            tracer->handle_instruction_execution(analysis->address);
        }
    } catch (const std::exception& e) {
        tracer->log_.trace("error in instruction callback", redlog::field("error", e.what()));
    }
    
    return static_cast<QBDIVMAction>(QBDI::VMAction::CONTINUE);
}

void w1cov_tracer::handle_basic_block_entry(uint64_t address, uint16_t size) {
    if (collector_) {
        collector_->record_basic_block(address, size);
    }
}

void w1cov_tracer::handle_instruction_execution(uint64_t address) {
    // detailed instruction-level tracing (optional)
    log_.trace("instruction executed", redlog::field("address", address));
}

bool w1cov_tracer::discover_and_register_modules() {
    if (!mapper_) {
        log_.error("module mapper not initialized");
        return false;
    }
    
    log_.info("discovering process modules");
    
    // try qbdi-based discovery first
    if (!mapper_->discover_qbdi_modules()) {
        log_.warn("qbdi module discovery failed, trying process-based discovery");
        
        if (!mapper_->discover_process_modules()) {
            log_.error("all module discovery methods failed");
            return false;
        }
    }
    
    // register discovered modules with collector
    size_t registered_count = mapper_->register_discovered_modules();
    
    log_.info("module discovery completed",
              redlog::field("total_regions", mapper_->get_total_regions()),
              redlog::field("executable_regions", mapper_->get_executable_count()),
              redlog::field("user_modules", mapper_->get_user_module_count()),
              redlog::field("registered_modules", registered_count));
    
    return registered_count > 0;
}

bool w1cov_tracer::setup_instrumentation_ranges() {
    if (!qbdi_vm_ || !mapper_) {
        log_.error("qbdi vm or mapper not initialized");
        return false;
    }
    
    log_.info("setting up instrumentation ranges");
    
    try {
        auto* vm = static_cast<QBDI::VM*>(qbdi_vm_);
        
        // get user modules to instrument
        auto user_modules = mapper_->get_user_modules();
        
        if (user_modules.empty()) {
            log_.warn("no user modules found for instrumentation");
            // fallback: instrument all executable regions
            vm->instrumentAllExecutableMaps();
            log_.info("instrumented all executable regions");
            return true;
        }
        
        // instrument specific modules
        for (const auto& region : user_modules) {
            vm->addInstrumentedRange(
                static_cast<QBDI::rword>(region.start),
                static_cast<QBDI::rword>(region.end)
            );
            
            log_.verbose("added instrumentation range",
                        redlog::field("start", region.start),
                        redlog::field("end", region.end),
                        redlog::field("name", region.name));
        }
        
        log_.info("instrumentation ranges configured",
                  redlog::field("range_count", user_modules.size()));
        
        return true;
        
    } catch (const std::exception& e) {
        log_.error("failed to setup instrumentation ranges", redlog::field("error", e.what()));
        return false;
    }
}

void w1cov_tracer::print_statistics() const {
    if (!collector_) {
        return;
    }
    
    size_t total_blocks = collector_->get_total_blocks();
    size_t unique_blocks = collector_->get_unique_blocks();
    auto coverage_stats = collector_->get_coverage_stats();
    
    log_.info("coverage statistics",
              redlog::field("total_basic_blocks", total_blocks),
              redlog::field("unique_basic_blocks", unique_blocks),
              redlog::field("modules_with_coverage", coverage_stats.size()));
    
    // log per-module statistics
    for (const auto& [module_id, block_count] : coverage_stats) {
        log_.verbose("module coverage",
                    redlog::field("module_id", module_id),
                    redlog::field("basic_blocks", block_count));
    }
}

bool w1cov_tracer::export_coverage_data() const {
    if (!collector_) {
        log_.error("collector not initialized");
        return false;
    }
    
    log_.info("exporting coverage data", redlog::field("output_file", output_file_));
    
    return collector_->write_drcov_file(output_file_);
}

size_t w1cov_tracer::get_basic_block_count() const {
    return collector_ ? collector_->get_total_blocks() : 0;
}

size_t w1cov_tracer::get_module_count() const {
    return mapper_ ? mapper_->get_total_regions() : 0;
}

std::string w1cov_tracer::get_env_var(const char* name, const std::string& default_value) const {
    const char* value = std::getenv(name);
    return value ? std::string(value) : default_value;
}

bool w1cov_tracer::get_env_bool(const char* name, bool default_value) const {
    const char* value = std::getenv(name);
    if (!value) {
        return default_value;
    }
    
    std::string str_value(value);
    std::transform(str_value.begin(), str_value.end(), str_value.begin(), ::tolower);
    
    return str_value == "1" || str_value == "true" || str_value == "yes" || str_value == "on";
}

// global instance
static w1cov_tracer g_tracer;

w1cov_tracer& get_global_tracer() {
    return g_tracer;
}

// library constructor/destructor
extern "C" {

void w1cov_initialize() {
    auto& tracer = get_global_tracer();
    
    // check if w1cov is enabled
    const char* enabled = std::getenv("W1COV_ENABLED");
    if (!enabled || std::strcmp(enabled, "1") != 0) {
        return; // not enabled
    }
    
    if (tracer.initialize()) {
        tracer.start_instrumentation();
    }
}

void w1cov_finalize() {
    auto& tracer = get_global_tracer();
    tracer.shutdown();
}

} // extern "C"

} // namespace w1::coverage