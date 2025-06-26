/**
 * @file w1cov_standalone.hpp
 * @brief Standalone API for w1cov coverage collection
 * 
 * This provides a simple API for using w1cov coverage collection
 * in standalone applications without QBDIPreload.
 */

#pragma once

#include "coverage_tracer.hpp"
#include "../../framework/callback_registrar.hpp"
#include <QBDI.h>
#include <memory>
#include <vector>

namespace w1::coverage {

/**
 * @brief Standalone coverage collection session
 * 
 * Provides a simple interface for standalone coverage collection:
 * 
 * ```cpp
 * coverage_session session;
 * session.initialize();
 * session.trace_function(my_function, {arg1, arg2});
 * session.export_coverage("output.drcov");
 * ```
 */
class coverage_session {
public:
    explicit coverage_session(const coverage_config& config = {});
    ~coverage_session();

    // === Lifecycle ===
    bool initialize();
    void shutdown();
    bool is_initialized() const;

    // === Configuration ===
    void set_output_file(const std::string& filepath);
    void set_debug_mode(bool debug);
    void add_target_module_pattern(const std::string& pattern);
    
    // === Instrumentation ===
    bool instrument_address_range(uint64_t start, uint64_t end);
    bool instrument_function(void* func_ptr);
    bool instrument_all_executable_memory();
    
    // === Execution ===
    bool trace_function(void* func_ptr, const std::vector<uint64_t>& args = {}, uint64_t* result = nullptr);
    bool trace_address_range(uint64_t start, uint64_t end);
    
    // === Data Export ===
    bool export_data(const std::string& output_path = "");
    void print_statistics() const;
    
    // === Statistics ===
    size_t get_basic_block_count() const;
    size_t get_unique_block_count() const;
    uint64_t get_total_hits() const;

    // === Advanced Access ===
    coverage_tracer* get_tracer() const { return tracer_.get(); }
    QBDI::VM* get_vm() const { return vm_.get(); }

private:
    std::unique_ptr<coverage_tracer> tracer_;
    std::unique_ptr<QBDI::VM> vm_;
    std::unique_ptr<w1::framework::callback_registrar<coverage_tracer>> registrar_;
    QBDI::GPRState* gpr_state_;
    bool initialized_;
    
    bool setup_qbdi_vm();
    bool allocate_virtual_stack();
};


// === Convenience Functions ===

/**
 * @brief Simple function tracing with coverage collection
 * 
 * @param func_ptr Function to trace
 * @param args Arguments to pass to function
 * @param output_file Coverage output file (default: w1cov.drcov)
 * @return true if successful
 */
bool trace_function_with_coverage(void* func_ptr, const std::vector<uint64_t>& args = {}, 
                                 const std::string& output_file = "w1cov.drcov");

/**
 * @brief Simple address range tracing with coverage collection
 * 
 * @param start Start address
 * @param end End address  
 * @param output_file Coverage output file (default: w1cov.drcov)
 * @return true if successful
 */
bool trace_range_with_coverage(uint64_t start, uint64_t end,
                              const std::string& output_file = "w1cov.drcov");

} // namespace w1::coverage