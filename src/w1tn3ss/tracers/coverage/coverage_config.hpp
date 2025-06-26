/**
 * @file coverage_config.hpp
 * @brief Unified configuration management for coverage tracing
 * 
 * This provides a single place for all configuration handling,
 * environment variable parsing, and validation.
 */

#pragma once

#include "w1cov_constants.hpp"
#include <redlog/redlog.hpp>
#include <string>
#include <vector>

namespace w1::coverage {

/**
 * @brief Unified configuration for coverage tracing
 */
struct coverage_config {
    // Output configuration
    std::string output_file = w1::cov::DEFAULT_OUTPUT_FILENAME;
    std::string output_format = w1::cov::DEFAULT_OUTPUT_FORMAT;
    
    // Module filtering
    bool exclude_system_modules = true;
    std::vector<std::string> target_modules;
    
    // Feature flags
    bool debug_mode = false;
    bool track_full_paths = false;
    bool auto_configure_from_env = true;
    
    // Performance tuning
    uint64_t progress_report_interval = w1::cov::PROGRESS_REPORT_INTERVAL;
};

/**
 * @brief Configuration manager for coverage tracing
 * 
 * Centralizes all configuration parsing, validation, and management.
 * Provides a clean interface while keeping environment variable handling
 * in one place.
 */
class coverage_config_manager {
public:
    explicit coverage_config_manager();
    
    // Configuration loading
    void load_from_environment(coverage_config& config);
    bool is_coverage_enabled() const;
    
    // Validation
    bool validate_config(const coverage_config& config) const;
    
    // Logging support
    void log_config(const coverage_config& config, redlog::logger& log) const;

private:
    redlog::logger log_;
    
    // Environment variable helpers  
    std::string get_env_var(const char* name, const std::string& default_value = "") const;
    bool get_env_bool(const char* name, bool default_value = false) const;
    std::vector<std::string> parse_comma_separated(const std::string& value) const;
};

} // namespace w1::coverage