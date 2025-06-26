/**
 * @file coverage_tracer.cpp
 * @brief Implementation of the clean coverage tracer
 */

#include "coverage_tracer.hpp"
#include "../../framework/module_discovery.hpp"
#include <QBDI.h>
#include <cstdlib>
#include <cstring>

namespace w1::coverage {

coverage_tracer::coverage_tracer(const coverage_config& config)
    : tracer_base(config, "coverage_tracer")
    , collector_(std::make_unique<coverage_collector>())
    , modules_(std::make_unique<w1::framework::module_discovery>())
    , env_config_("W1COV") {
    
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
        log_.warn("coverage tracer already initialized");
        return true;
    }

    log_.info("initializing coverage tracer", 
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
    log_.info("coverage tracer initialized successfully");
    return true;
}

void coverage_tracer::shutdown() {
    if (!is_initialized()) {
        return;
    }

    log_.info("shutting down coverage tracer");
    
    // Print final statistics
    if (config_.debug_mode) {
        print_summary();
    }

    set_initialized(false);
    log_.info("coverage tracer shutdown completed");
}

bool coverage_tracer::export_data(const std::string& output_path) {
    if (!is_initialized()) {
        log_.error("cannot export data - tracer not initialized");
        return false;
    }

    log_.info("exporting coverage data", redlog::field("output_path", output_path));

    try {
        bool success = collector_->write_drcov_file(output_path);
        
        if (success) {
            log_.info("coverage data exported successfully", redlog::field("output_path", output_path));
            print_summary();
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

    // Check if coverage is enabled
    const char* enabled = getenv(w1::cov::ENV_W1COV_ENABLED);
    if (!enabled || strcmp(enabled, w1::cov::ENABLED_VALUE) != 0) {
        log_.debug("coverage not enabled via environment");
        return;
    }

    // Output file
    const char* output = getenv(w1::cov::ENV_W1COV_OUTPUT_FILE);
    if (output) {
        config_.output_file = output;
        log_.debug("output file from environment", redlog::field("file", output));
    }

    // Debug mode
    const char* debug = getenv(w1::cov::ENV_W1COV_DEBUG);
    if (debug && strcmp(debug, w1::cov::ENABLED_VALUE) == 0) {
        config_.debug_mode = true;
        log_.debug("debug mode enabled via environment");
    }

    // System module exclusion
    const char* exclude_system = getenv(w1::cov::ENV_W1COV_EXCLUDE_SYSTEM);
    if (exclude_system) {
        config_.exclude_system_modules = (strcmp(exclude_system, w1::cov::ENABLED_VALUE) == 0);
        log_.debug("exclude system modules", redlog::field("exclude", config_.exclude_system_modules));
    }

    // Track full paths
    const char* full_paths = getenv(w1::cov::ENV_W1COV_TRACK_FULL_PATHS);
    if (full_paths && strcmp(full_paths, w1::cov::ENABLED_VALUE) == 0) {
        config_.track_full_paths = true;
        log_.debug("track full paths enabled via environment");
    }

    // Output format
    const char* format = getenv(w1::cov::ENV_W1COV_FORMAT);
    if (format) {
        config_.output_format = format;
        log_.debug("output format from environment", redlog::field("format", format));
    }

    // Target modules (comma-separated)
    const char* targets = getenv(w1::cov::ENV_W1COV_TARGET_MODULES);
    if (targets) {
        std::string target_str(targets);
        // Simple comma-separated parsing
        size_t pos = 0;
        while ((pos = target_str.find(',')) != std::string::npos) {
            std::string pattern = target_str.substr(0, pos);
            if (!pattern.empty()) {
                config_.target_modules.push_back(pattern);
            }
            target_str.erase(0, pos + 1);
        }
        if (!target_str.empty()) {
            config_.target_modules.push_back(target_str);
        }
        
        log_.debug("target modules from environment", 
                  redlog::field("count", config_.target_modules.size()));
    }
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
    log_.info("  Total Basic Blocks", redlog::field("count", format_number(get_basic_block_count())));
    log_.info("  Unique Blocks", redlog::field("count", format_number(get_unique_block_count())));
    log_.info("  Total Hits", redlog::field("count", format_number(get_total_hits())));
    log_.info("  Modules", redlog::field("count", stats.size()));
    
    if (config_.debug_mode && !stats.empty()) {
        log_.info("  Per-Module Coverage:");
        for (const auto& [module_id, block_count] : stats) {
            log_.info("    Module coverage", 
                     redlog::field("module_id", module_id),
                     redlog::field("blocks", format_number(block_count)));
        }
    }
}

void coverage_tracer::print_summary() const {
    w1::cov::log("Coverage Summary:");
    w1::cov::log("        Basic Blocks: %s", format_number(get_unique_block_count()).c_str());
    w1::cov::log("        Total Hits:   %s", format_number(get_total_hits()).c_str());
    w1::cov::log("        Modules:      %s", format_number(get_module_count()).c_str());
    w1::cov::log("Coverage exported -> %s", config_.output_file.c_str());
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
                              redlog::field("start", map.range.start()),
                              redlog::field("end", map.range.end()),
                              redlog::field("size", map.range.end() - map.range.start()));
                }
            }
        }

        log_.info("module discovery completed", 
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

    // This is a simplified cache - in practice, we'd need to extract
    // hitcounts from the coverage_collector. For now, we'll leave it empty
    // since the current coverage_collector doesn't expose hitcounts directly.
    hitcounts_cache_.clear();
    
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
            w1::cov::log("Traced %s basic blocks, %s unique blocks", 
                        format_number(current_count).c_str(),
                        format_number(get_unique_block_count()).c_str());
        }
    }
}

// === Factory Functions ===

std::unique_ptr<coverage_tracer> create_coverage_tracer(const coverage_config& config) {
    return std::make_unique<coverage_tracer>(config);
}

bool is_coverage_enabled() {
    const char* enabled = getenv(w1::cov::ENV_W1COV_ENABLED);
    return enabled && strcmp(enabled, w1::cov::ENABLED_VALUE) == 0;
}

std::unique_ptr<coverage_tracer> create_coverage_tracer_from_env() {
    coverage_config config;
    config.auto_configure_from_env = true;
    return std::make_unique<coverage_tracer>(config);
}

} // namespace w1::coverage