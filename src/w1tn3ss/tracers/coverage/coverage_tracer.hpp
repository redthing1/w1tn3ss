/**
 * @file coverage_tracer.hpp
 * @brief Clean, elegant coverage tracer implementation
 * 
 * This is the core coverage tracer that tracks basic block execution
 * and exports coverage data in DrCov format. Built on the w1tn3ss framework
 * for shared utilities while keeping coverage-specific logic clean.
 */

#pragma once

#include "../../framework/tracer_base.hpp"
#include "../../framework/module_discovery.hpp"
#include "coverage_data.hpp"
#include "coverage_config.hpp"

#include <redlog/redlog.hpp>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace w1::coverage {

// Configuration is now defined in coverage_config.hpp

/**
 * @brief Clean coverage tracer implementation
 * 
 * Features:
 * - Basic block coverage tracking with hitcounts
 * - Module discovery and address mapping
 * - DrCov format export for analysis tools
 * - Environment variable configuration
 * - Thread-safe data collection
 * - Progress reporting and statistics
 * 
 * Usage:
 * ```cpp
 * coverage_tracer tracer;
 * tracer.initialize();
 * // Use with callback_registrar to register QBDI callbacks
 * // Coverage is collected via on_basic_block() calls
 * tracer.export_data("output.drcov");
 * ```
 */
class coverage_tracer : public w1::framework::tracer_base<coverage_config> {
public:
    explicit coverage_tracer(const coverage_config& config = {});
    ~coverage_tracer();

    // === Framework Interface ===
    
    bool initialize() override;
    void shutdown() override;
    bool export_data(const std::string& output_path) override;

    // === Configuration ===
    
    void configure_from_environment();
    void set_output_file(const std::string& filepath);
    void set_exclude_system_modules(bool exclude);
    void add_target_module_pattern(const std::string& pattern);
    void set_debug_mode(bool debug);

    // === QBDI Callback (Framework Auto-Detection) ===
    
    /**
     * @brief Basic block callback - automatically detected by framework
     * 
     * This method is called by QBDI for every basic block execution.
     * The framework's callback_registrar will detect this method via SFINAE
     * and register it automatically.
     * 
     * @param address Basic block start address
     * @param size Basic block size in bytes
     */
    void on_basic_block(uint64_t address, uint16_t size);

    // === Data Access and Statistics ===
    
    size_t get_basic_block_count() const;
    size_t get_unique_block_count() const;
    size_t get_module_count() const;
    uint32_t get_hitcount(uint64_t address) const;
    uint64_t get_total_hits() const;
    
    void print_statistics() const;

    // === Direct Access (for advanced usage) ===
    
    const std::unordered_map<uint64_t, uint32_t>& get_hitcounts() const;
    coverage_collector* get_collector() const { return collector_.get(); }

private:
    // === Coverage Data ===
    std::unique_ptr<coverage_collector> collector_;
    std::unique_ptr<w1::framework::module_discovery> modules_;
    std::unique_ptr<coverage_config_manager> config_manager_;

    // Fast access cache for hitcounts
    mutable std::unordered_map<uint64_t, uint32_t> hitcounts_cache_;
    mutable std::atomic<bool> hitcounts_dirty_{true};
    mutable std::mutex cache_mutex_;

    // Statistics
    std::atomic<uint64_t> basic_block_count_{0};
    std::atomic<uint64_t> last_progress_report_{0};

    // === Internal Methods ===
    
    bool discover_and_register_modules();
    void sync_hitcounts_cache() const;
    void invalidate_hitcounts_cache();
    void report_progress_if_needed();
};

// === Factory Functions ===

/**
 * @brief Create coverage tracer with default configuration
 */
std::unique_ptr<coverage_tracer> create_coverage_tracer(const coverage_config& config = {});

/**
 * @brief Check if coverage is enabled via environment
 */
bool is_coverage_enabled();

/**
 * @brief Create coverage tracer configured from environment variables
 */
std::unique_ptr<coverage_tracer> create_coverage_tracer_from_env();

} // namespace w1::coverage