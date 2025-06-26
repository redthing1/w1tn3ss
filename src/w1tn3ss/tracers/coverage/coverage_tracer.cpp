/**
 * @file coverage_tracer.cpp
 * @brief Implementation of the clean coverage tracer
 */

#include "coverage_tracer.hpp"
#include "../../framework/module_discovery.hpp"
#include "../../framework/utils.hpp"
#include <QBDI.h>
#include <filesystem>

namespace w1::coverage {


coverage_tracer::coverage_tracer(const coverage_config& config)
    : tracer_base(config, "coverage_tracer")
    , collector_(std::make_unique<coverage_collector>())
    , modules_(std::make_unique<w1::framework::module_discovery>())
    , config_manager_(std::make_unique<coverage_config_manager>()) {
    
    log_.debug("coverage tracer created");
    
    if (config_.auto_configure_from_env) {
        configure_from_environment();
    }
}

coverage_tracer::~coverage_tracer() {
    if (is_initialized()) {
        shutdown();
    }
    log_.debug("coverage tracer destroyed");
}

bool coverage_tracer::initialize() {
    if (is_initialized()) {
        log_.debug("coverage tracer already initialized");
        return true;
    }

    // Configure global logging level based on debug mode
    if (config_.debug_mode) {
        redlog::set_level(redlog::level::trace);
        log_.info("enabled debug logging for coverage tracing");
    }

    log_.debug("initializing coverage tracer", 
             redlog::field("output_file", config_.output_file),
             redlog::field("debug_mode", config_.debug_mode));

    // Configure collector
    collector_->set_exclude_system_modules(config_.exclude_system_modules);
    collector_->set_output_file(config_.output_file);

    // Discover and register modules
    if (!discover_and_register_modules()) {
        log_.error("failed to discover modules");
        return false;
    }

    // Reset statistics
    basic_block_count_.store(0);
    last_progress_report_.store(0);
    invalidate_hitcounts_cache();

    set_initialized(true);
    log_.debug("coverage tracer initialized successfully");
    return true;
}

void coverage_tracer::shutdown() {
    if (!is_initialized()) {
        return;
    }

    log_.debug("shutting down coverage tracer");
    
    // Export coverage data during shutdown
    export_data(config_.output_file);

    set_initialized(false);
    log_.debug("coverage tracer shutdown completed");
}

bool coverage_tracer::export_data(const std::string& output_path) {
    if (!is_initialized()) {
        log_.error("cannot export data - tracer not initialized");
        return false;
    }

    log_.debug("exporting coverage data", redlog::field("output_path", output_path));

    // Collect statistics before export
    auto stats = collector_->get_coverage_stats();
    size_t total_blocks = collector_->get_total_blocks();
    size_t unique_blocks = collector_->get_unique_blocks();
    uint64_t total_hits = collector_->get_total_hits();
    
    try {
        bool success = collector_->write_drcov_file(output_path);
        
        if (success) {
            // Verify file was actually created
            if (!std::filesystem::exists(output_path)) {
                log_.error("coverage file was not created", redlog::field("path", output_path));
                return false;
            }
            
            // Show neat statistics at info level
            log_.info("Coverage collection completed successfully");
            log_.info("  Basic blocks:     " + std::to_string(unique_blocks) + " unique, " + std::to_string(total_hits) + " total executions");
            log_.info("  Average hits:     " + std::to_string(unique_blocks > 0 ? (double)total_hits / unique_blocks : 0.0));
            log_.info("  Modules traced:   " + std::to_string(stats.size()));
            log_.info("  Output file:      " + output_path);
            
            log_.debug("coverage data exported successfully", redlog::field("output_path", output_path));
        } else {
            log_.error("failed to export coverage data", redlog::field("output_path", output_path));
        }
        
        return success;
        
    } catch (const std::exception& e) {
        log_.error("exception during coverage export", 
                  redlog::field("output_path", output_path),
                  redlog::field("error", e.what()));
        return false;
    }
}

void coverage_tracer::configure_from_environment() {
    log_.debug("configuring from environment variables");
    
    if (!config_manager_) {
        log_.error("config manager not initialized");
        return;
    }
    
    // Use the config manager to load from environment
    config_manager_->load_from_environment(config_);
    
    // Validate the configuration
    if (!config_manager_->validate_config(config_)) {
        log_.error("invalid configuration loaded from environment");
        return;
    }
    
    // Log the final configuration
    config_manager_->log_config(config_, log_);
}

void coverage_tracer::set_output_file(const std::string& filepath) {
    config_.output_file = filepath;
    if (collector_) {
        collector_->set_output_file(filepath);
    }
    log_.debug("output file set", redlog::field("file", filepath));
}

void coverage_tracer::set_exclude_system_modules(bool exclude) {
    config_.exclude_system_modules = exclude;
    if (collector_) {
        collector_->set_exclude_system_modules(exclude);
    }
    log_.debug("exclude system modules", redlog::field("exclude", exclude));
}

void coverage_tracer::add_target_module_pattern(const std::string& pattern) {
    config_.target_modules.push_back(pattern);
    log_.debug("added target module pattern", redlog::field("pattern", pattern));
}

void coverage_tracer::set_debug_mode(bool debug) {
    config_.debug_mode = debug;
    log_.debug("debug mode", redlog::field("debug", debug));
}

void coverage_tracer::on_basic_block(uint64_t address, uint16_t size) {
    if (!is_initialized()) {
        return;
    }

    // Record basic block
    collector_->record_basic_block(address, size);
    
    // Update statistics
    uint64_t count = basic_block_count_.fetch_add(1) + 1;
    
    // Invalidate hitcounts cache
    invalidate_hitcounts_cache();
    
    // Progress reporting
    if (config_.debug_mode && (count % config_.progress_report_interval == 0)) {
        report_progress_if_needed();
    }
}

size_t coverage_tracer::get_basic_block_count() const {
    return basic_block_count_.load();
}

size_t coverage_tracer::get_unique_block_count() const {
    if (!collector_) return 0;
    return collector_->get_unique_blocks();
}

size_t coverage_tracer::get_module_count() const {
    if (!collector_) return 0;
    // Get module count from collector's coverage stats
    auto stats = collector_->get_coverage_stats();
    return stats.size();
}

uint32_t coverage_tracer::get_hitcount(uint64_t address) const {
    sync_hitcounts_cache();
    auto it = hitcounts_cache_.find(address);
    return (it != hitcounts_cache_.end()) ? it->second : 0;
}

uint64_t coverage_tracer::get_total_hits() const {
    sync_hitcounts_cache();
    uint64_t total = 0;
    for (const auto& [addr, count] : hitcounts_cache_) {
        total += count;
    }
    return total;
}

void coverage_tracer::print_statistics() const {
    if (!is_initialized()) {
        log_.info("Coverage tracer not initialized");
        return;
    }

    auto stats = collector_->get_coverage_stats();
    
    log_.info("Coverage Statistics:");
    log_.info("  Total Basic Blocks", redlog::field("count", w1::framework::utils::format_number(get_basic_block_count())));
    log_.info("  Unique Blocks", redlog::field("count", w1::framework::utils::format_number(get_unique_block_count())));
    log_.info("  Total Hits", redlog::field("count", w1::framework::utils::format_number(get_total_hits())));
    log_.info("  Modules", redlog::field("count", stats.size()));
    
    if (config_.debug_mode && !stats.empty()) {
        log_.info("  Per-Module Coverage:");
        for (const auto& [module_id, block_count] : stats) {
            log_.info("    Module coverage", 
                     redlog::field("module_id", module_id),
                     redlog::field("blocks", w1::framework::utils::format_number(block_count)));
        }
    }
}


const std::unordered_map<uint64_t, uint32_t>& coverage_tracer::get_hitcounts() const {
    sync_hitcounts_cache();
    return hitcounts_cache_;
}

bool coverage_tracer::discover_and_register_modules() {
    log_.debug("discovering executable modules");

    try {
        std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);
        
        if (maps.empty()) {
            log_.error("failed to get process memory maps");
            return false;
        }

        size_t registered_count = 0;
        
        // Register executable modules with collector
        for (const auto& map : maps) {
            if (!(map.permission & QBDI::PF_EXEC)) {
                continue;
            }

            std::string module_name = map.name.empty() ? "unknown" : map.name;
            uint16_t module_id = collector_->add_module(
                module_name, 
                map.range.start(), 
                map.range.end(), 
                0  // entry point unknown
            );
            
            if (module_id != UINT16_MAX) {
                registered_count++;
                
                if (config_.debug_mode) {
                    log_.debug("registered module",
                              redlog::field("id", module_id),
                              redlog::field("name", module_name),
                              redlog::field("start", w1::framework::utils::format_hex(map.range.start())),
                              redlog::field("end", w1::framework::utils::format_hex(map.range.end())),
                              redlog::field("size", map.range.end() - map.range.start()));
                }
            }
        }

        log_.debug("module discovery completed", 
                 redlog::field("total_maps", maps.size()),
                 redlog::field("registered", registered_count));

        return registered_count > 0;
        
    } catch (const std::exception& e) {
        log_.error("module discovery failed", redlog::field("error", e.what()));
        return false;
    }
}

void coverage_tracer::sync_hitcounts_cache() const {
    if (!hitcounts_dirty_.load()) {
        return;
    }

    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // Double-check pattern
    if (!hitcounts_dirty_.load()) {
        return;
    }

    // Get hitcounts from collector
    if (collector_) {
        hitcounts_cache_ = collector_->get_hitcounts();
    } else {
        hitcounts_cache_.clear();
    }
    
    hitcounts_dirty_.store(false);
}

void coverage_tracer::invalidate_hitcounts_cache() {
    hitcounts_dirty_.store(true);
}

void coverage_tracer::report_progress_if_needed() {
    uint64_t current_count = basic_block_count_.load();
    uint64_t last_report = last_progress_report_.load();
    
    if (current_count - last_report >= config_.progress_report_interval) {
        if (last_progress_report_.compare_exchange_weak(last_report, current_count)) {
            log_.debug("Coverage progress", 
                     redlog::field("traced_blocks", current_count),
                     redlog::field("unique_blocks", get_unique_block_count()));
        }
    }
}

// === Factory Functions ===

std::unique_ptr<coverage_tracer> create_coverage_tracer(const coverage_config& config) {
    return std::make_unique<coverage_tracer>(config);
}

bool is_coverage_enabled() {
    coverage_config_manager config_manager;
    return config_manager.is_coverage_enabled();
}

std::unique_ptr<coverage_tracer> create_coverage_tracer_from_env() {
    coverage_config config;
    config.auto_configure_from_env = true;
    return std::make_unique<coverage_tracer>(config);
}

} // namespace w1::coverage