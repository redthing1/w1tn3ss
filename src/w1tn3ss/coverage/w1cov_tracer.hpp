#pragma once

#include <memory>
#include <string>
#include <atomic>
#include <chrono>
#include <redlog/redlog.hpp>

// opaque pointer for QBDI types to avoid header conflicts
typedef void* QBDIVMPtr;
typedef void* QBDIGPRStatePtr;
typedef void* QBDIFPRStatePtr;
typedef void* QBDIVMStatePtr;
typedef int QBDIVMAction;

namespace w1::coverage {

class coverage_collector;
class module_mapper;

class w1cov_tracer {
public:
    w1cov_tracer();
    ~w1cov_tracer();
    
    // lifecycle management
    bool initialize();
    void shutdown();
    bool is_initialized() const { return initialized_; }
    
    // configuration
    void configure_from_environment();
    void set_output_file(const std::string& filepath);
    void set_exclude_system_modules(bool exclude);
    void add_target_module_pattern(const std::string& pattern);
    
    // instrumentation control
    bool start_instrumentation();
    bool stop_instrumentation();
    bool is_instrumenting() const { return instrumenting_; }
    
    // target execution
    bool instrument_current_process();
    bool instrument_address_range(uint64_t start, uint64_t end);
    bool instrument_module_by_name(const std::string& module_name);
    
    // statistics and reporting
    void print_statistics() const;
    bool export_coverage_data() const;
    size_t get_basic_block_count() const;
    size_t get_module_count() const;
    
private:
    redlog::logger log_;
    std::atomic<bool> initialized_;
    std::atomic<bool> instrumenting_;
    
    // core components
    QBDIVMPtr qbdi_vm_;
    std::unique_ptr<coverage_collector> collector_;
    std::unique_ptr<module_mapper> mapper_;
    
    // configuration
    std::string output_file_;
    bool exclude_system_;
    
    // performance monitoring
    mutable std::atomic<uint64_t> callback_count_;
    mutable std::atomic<uint64_t> instrumentation_start_time_;
    mutable std::atomic<uint64_t> last_stats_time_;
    
    // qbdi setup and callbacks
    bool setup_qbdi_vm();
    bool register_callbacks();
    void cleanup_qbdi_vm();
    
    // qbdi callbacks (static methods for c-style callbacks)
    static QBDIVMAction basic_block_callback(
        QBDIVMPtr vm, 
        QBDIVMStatePtr vmState,
        QBDIGPRStatePtr gprState, 
        QBDIFPRStatePtr fprState, 
        void* data
    );
    
    static QBDIVMAction instruction_callback(
        QBDIVMPtr vm,
        QBDIGPRStatePtr gprState,
        QBDIFPRStatePtr fprState,
        void* data
    );
    
    // callback implementation details
    void handle_basic_block_entry(uint64_t address, uint16_t size);
    void handle_instruction_execution(uint64_t address);
    
    // module discovery and instrumentation
    bool discover_and_register_modules();
    bool setup_instrumentation_ranges();
    
    // environment variable helpers
    std::string get_env_var(const char* name, const std::string& default_value = "") const;
    bool get_env_bool(const char* name, bool default_value = false) const;
};

// global tracer instance for easy access
w1cov_tracer& get_global_tracer();

// initialization helper for library loading
extern "C" {
    // called when library is loaded
    void w1cov_initialize() __attribute__((constructor));
    
    // called when library is unloaded
    void w1cov_finalize() __attribute__((destructor));
}

} // namespace w1::coverage