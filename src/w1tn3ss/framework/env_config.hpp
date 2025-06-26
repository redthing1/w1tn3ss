/**
 * @file env_config.hpp
 * @brief Generic environment variable configuration utilities for w1tn3ss framework
 * 
 * This component provides type-safe, reusable environment variable parsing
 * that can be used by any tracer implementation.
 */

#pragma once

#include <redlog/redlog.hpp>
#include <string>
#include <vector>
#include <sstream>
#include <type_traits>
#include <cstdlib>
#include <algorithm>
#include <cctype>

namespace w1::framework {

/**
 * @brief Generic environment variable configuration parser
 * 
 * Template-based configuration parser that provides type-safe environment
 * variable parsing with default values and validation.
 */
template<typename ConfigType>
class env_config {
public:
    explicit env_config(const std::string& prefix = "")
        : log_(redlog::get_logger("w1tn3ss.env_config")), prefix_(prefix) {
        if (!prefix_.empty() && prefix_.back() != '_') {
            prefix_ += '_';
        }
    }

    /**
     * @brief Parse configuration from environment variables
     * @param config Configuration object to populate
     */
    void parse_from_environment(ConfigType& config) {
        log_.debug("parsing configuration from environment", redlog::field("prefix", prefix_));
        
        // Let the config type handle its own parsing via specialization
        parse_config_impl(config);
        
        log_.debug("environment configuration parsing completed");
    }

    /**
     * @brief Get boolean value from environment variable
     */
    bool get_env_bool(const char* name, bool default_value = false) const {
        const char* value = std::getenv(name);
        if (!value) {
            return default_value;
        }

        std::string str_value(value);
        std::transform(str_value.begin(), str_value.end(), str_value.begin(), ::tolower);

        bool result = str_value == "1" || str_value == "true" || str_value == "yes" || str_value == "on";
        
        log_.trace("parsed boolean environment variable", 
                  redlog::field("name", name), 
                  redlog::field("value", value),
                  redlog::field("parsed", result));
        
        return result;
    }

    /**
     * @brief Get string value from environment variable
     */
    std::string get_env_string(const char* name, const std::string& default_value = "") const {
        const char* value = std::getenv(name);
        std::string result = value ? std::string(value) : default_value;
        
        log_.trace("parsed string environment variable",
                  redlog::field("name", name),
                  redlog::field("value", result));
        
        return result;
    }

    /**
     * @brief Get integer value from environment variable
     */
    template<typename IntType>
    IntType get_env_int(const char* name, IntType default_value = IntType{}) const {
        static_assert(std::is_integral_v<IntType>, "IntType must be an integral type");
        
        const char* value = std::getenv(name);
        if (!value) {
            return default_value;
        }

        try {
            if constexpr (std::is_same_v<IntType, int>) {
                return std::stoi(value);
            } else if constexpr (std::is_same_v<IntType, long>) {
                return std::stol(value);
            } else if constexpr (std::is_same_v<IntType, long long>) {
                return std::stoll(value);
            } else if constexpr (std::is_same_v<IntType, unsigned int>) {
                return static_cast<unsigned int>(std::stoul(value));
            } else if constexpr (std::is_same_v<IntType, unsigned long>) {
                return std::stoul(value);
            } else if constexpr (std::is_same_v<IntType, unsigned long long>) {
                return std::stoull(value);
            } else {
                // For other integral types, use long long as intermediate
                return static_cast<IntType>(std::stoll(value));
            }
        } catch (const std::exception& e) {
            log_.warn("failed to parse integer environment variable",
                     redlog::field("name", name),
                     redlog::field("value", value),
                     redlog::field("error", e.what()),
                     redlog::field("using_default", default_value));
            return default_value;
        }
    }

    /**
     * @brief Get comma-separated list from environment variable
     */
    std::vector<std::string> get_env_list(const char* name, const std::vector<std::string>& default_value = {}) const {
        std::string value = get_env_string(name);
        if (value.empty()) {
            return default_value;
        }

        std::vector<std::string> result;
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

        log_.trace("parsed list environment variable",
                  redlog::field("name", name),
                  redlog::field("count", result.size()));

        return result;
    }

    /**
     * @brief Check if environment variable is set
     */
    bool is_env_set(const char* name) const {
        return std::getenv(name) != nullptr;
    }

    /**
     * @brief Get prefixed environment variable name
     */
    std::string prefixed_name(const std::string& name) const {
        return prefix_ + name;
    }

private:
    redlog::logger log_;
    std::string prefix_;

    // Default implementation - does nothing
    // Specialize this for specific config types
    void parse_config_impl(ConfigType& config) {
        static_assert(sizeof(ConfigType) == 0, 
                     "env_config must be specialized for your config type");
    }
};

/**
 * @brief Common environment variable patterns
 */
namespace env_patterns {
    constexpr const char* ENABLED = "ENABLED";
    constexpr const char* OUTPUT_FILE = "OUTPUT_FILE";
    constexpr const char* DEBUG = "DEBUG";
    constexpr const char* VERBOSE = "VERBOSE";
    constexpr const char* EXCLUDE_SYSTEM = "EXCLUDE_SYSTEM";
    constexpr const char* TARGET_MODULES = "TARGET_MODULES";
    constexpr const char* FORMAT = "FORMAT";
    constexpr const char* LOG_LEVEL = "LOG_LEVEL";
}

/**
 * @brief Utility functions for common patterns
 */
namespace env_utils {
    
    /**
     * @brief Check if tracing is enabled via environment
     */
    template<const char* PREFIX>
    bool is_enabled() {
        std::string var_name = std::string(PREFIX) + "_" + env_patterns::ENABLED;
        const char* value = std::getenv(var_name.c_str());
        return value && std::string(value) == "1";
    }

    /**
     * @brief Get log level from environment
     */
    inline redlog::level get_log_level(const char* var_name, redlog::level default_level = redlog::level::info) {
        const char* value = std::getenv(var_name);
        if (!value) {
            return default_level;
        }

        std::string level_str(value);
        std::transform(level_str.begin(), level_str.end(), level_str.begin(), ::tolower);

        if (level_str == "trace") return redlog::level::trace;
        if (level_str == "debug") return redlog::level::debug;
        if (level_str == "info") return redlog::level::info;
        if (level_str == "warn" || level_str == "warning") return redlog::level::warn;
        if (level_str == "error") return redlog::level::error;
        // Note: redlog may not have 'off' level, use error as highest

        return default_level;
    }
}

} // namespace w1::framework