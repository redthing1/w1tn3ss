/**
 * @file coverage_config.cpp
 * @brief Implementation of unified configuration management
 */

#include "coverage_config.hpp"
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace w1::coverage {

coverage_config_manager::coverage_config_manager() 
    : log_(redlog::get_logger("w1tn3ss.coverage.config")) {
}

void coverage_config_manager::load_from_environment(coverage_config& config) {
    log_.debug("loading configuration from environment variables");
    
    // Check if coverage is enabled
    if (!is_coverage_enabled()) {
        log_.debug("coverage not enabled via environment");
        return;
    }
    
    // Output configuration
    config.output_file = get_env_var(w1::cov::ENV_W1COV_OUTPUT_FILE, config.output_file);
    config.output_format = get_env_var(w1::cov::ENV_W1COV_FORMAT, config.output_format);
    
    // Module filtering
    config.exclude_system_modules = get_env_bool(w1::cov::ENV_W1COV_EXCLUDE_SYSTEM, config.exclude_system_modules);
    
    auto target_modules_str = get_env_var(w1::cov::ENV_W1COV_TARGET_MODULES);
    if (!target_modules_str.empty()) {
        config.target_modules = parse_comma_separated(target_modules_str);
    }
    
    // Feature flags
    config.debug_mode = get_env_bool(w1::cov::ENV_W1COV_DEBUG, config.debug_mode);
    config.track_full_paths = get_env_bool(w1::cov::ENV_W1COV_TRACK_FULL_PATHS, config.track_full_paths);
    
    log_.debug("configuration loaded from environment");
}

bool coverage_config_manager::is_coverage_enabled() const {
    return get_env_bool(w1::cov::ENV_W1COV_ENABLED, false);
}

bool coverage_config_manager::validate_config(const coverage_config& config) const {
    // Validate output file path
    if (config.output_file.empty()) {
        log_.error("output file cannot be empty");
        return false;
    }
    
    // Validate output format
    if (config.output_format != "drcov" && config.output_format != "text") {
        log_.error("unsupported output format", redlog::field("format", config.output_format));
        return false;
    }
    
    // Validate progress report interval
    if (config.progress_report_interval == 0) {
        log_.error("progress report interval cannot be zero");
        return false;
    }
    
    return true;
}

void coverage_config_manager::log_config(const coverage_config& config, redlog::logger& log) const {
    log.debug("Coverage Configuration:");
    log.debug("  Output File", redlog::field("file", config.output_file));
    log.debug("  Output Format", redlog::field("format", config.output_format));
    log.debug("  Exclude System Modules", redlog::field("exclude", config.exclude_system_modules));
    log.debug("  Debug Mode", redlog::field("debug", config.debug_mode));
    log.debug("  Track Full Paths", redlog::field("full_paths", config.track_full_paths));
    log.debug("  Progress Report Interval", redlog::field("interval", config.progress_report_interval));
    
    if (!config.target_modules.empty()) {
        log.debug("  Target Modules", redlog::field("count", config.target_modules.size()));
        for (const auto& pattern : config.target_modules) {
            log.debug("    Pattern", redlog::field("pattern", pattern));
        }
    }
}

std::string coverage_config_manager::get_env_var(const char* name, const std::string& default_value) const {
    const char* value = getenv(name);
    if (value) {
        log_.trace("environment variable found", redlog::field("name", name), redlog::field("value", value));
        return std::string(value);
    }
    return default_value;
}

bool coverage_config_manager::get_env_bool(const char* name, bool default_value) const {
    const char* value = getenv(name);
    if (value) {
        bool result = (strcmp(value, w1::cov::ENABLED_VALUE) == 0);
        log_.trace("environment boolean found", redlog::field("name", name), redlog::field("value", result));
        return result;
    }
    return default_value;
}

std::vector<std::string> coverage_config_manager::parse_comma_separated(const std::string& value) const {
    std::vector<std::string> result;
    
    if (value.empty()) {
        return result;
    }
    
    std::stringstream ss(value);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        // Trim whitespace  
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    
    log_.trace("parsed comma-separated values", redlog::field("count", result.size()));
    return result;
}

} // namespace w1::coverage