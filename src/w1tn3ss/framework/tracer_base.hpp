/**
 * @file tracer_base.hpp
 * @brief Base classes and utilities for w1tn3ss tracer implementations
 * 
 * This component provides optional base classes and utility functions that
 * tracers can use. The framework uses SFINAE detection, so implementing
 * these interfaces is optional - tracers can define their own signatures.
 */

#pragma once

#include <redlog/redlog.hpp>
#include <string>
#include <vector>
#include <memory>
#include <atomic>

namespace w1::framework {

/**
 * @brief Minimal tracer interface (optional)
 * 
 * Tracers don't need to inherit from this - the framework uses SFINAE
 * to detect available callback methods. This interface is provided for
 * convenience and documentation purposes.
 */
class tracer_interface {
public:
    virtual ~tracer_interface() = default;

    // Lifecycle methods
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    virtual bool is_initialized() const = 0;

    // Data export
    virtual bool export_data(const std::string& output_path) = 0;
};

/**
 * @brief Callback signatures that the framework can detect via SFINAE
 * 
 * These are the callback signatures that callback_registrar will detect.
 * Tracers can implement any subset of these methods:
 * 
 * - void on_basic_block(uint64_t address, uint16_t size)
 * - void on_instruction(uint64_t address)  
 * - void on_memory_access(uint64_t address, size_t size, bool is_write)
 */

/**
 * @brief Example tracer implementation showing callback signatures
 */
class example_tracer {
public:
    // Framework lifecycle
    bool initialize() { return true; }
    void shutdown() {}
    bool is_initialized() const { return true; }

    bool export_data(const std::string& output_path) { return true; }

    // QBDI callbacks - implement only what you need
    void on_basic_block(uint64_t address, uint16_t size) {
        // Handle basic block execution
    }

    void on_instruction(uint64_t address) {
        // Handle individual instruction execution
    }

    void on_memory_access(uint64_t address, size_t size, bool is_write) {
        // Handle memory read/write operations
    }
};

/**
 * @brief Tracer configuration base
 */
struct tracer_config_base {
    std::string output_file;
    bool verbose_logging = false;
    std::vector<std::string> target_modules;
    bool exclude_system_modules = true;
    bool debug_mode = false;
};

/**
 * @brief Factory function type for creating tracers
 */
template<typename TracerType, typename ConfigType>
using tracer_factory = std::unique_ptr<TracerType>(*)(const ConfigType& config);

/**
 * @brief Utility base class for tracer implementations
 * 
 * Provides common functionality that most tracers will need:
 * - Structured logging with redlog
 * - Configuration management
 * - Basic lifecycle tracking
 * - Thread-safe state management
 * 
 * Usage is optional - tracers can implement their own patterns.
 */
template<typename ConfigType>
class tracer_base : public tracer_interface {
public:
    explicit tracer_base(const ConfigType& config, const std::string& name = "tracer") 
        : config_(config), log_(redlog::get_logger("w1tn3ss." + name)), initialized_(false) {
        log_.debug("tracer created", redlog::field("name", name));
    }

    virtual ~tracer_base() {
        if (initialized_.load()) {
            log_.warn("tracer destroyed while still initialized");
        }
        log_.debug("tracer destroyed");
    }

    bool is_initialized() const override { return initialized_.load(); }
    
    const ConfigType& get_config() const { return config_; }

protected:
    // Configuration and logging
    ConfigType config_;
    redlog::logger log_;
    
    // Thread-safe state
    std::atomic<bool> initialized_;

    /**
     * @brief Set initialization state
     */
    void set_initialized(bool state) {
        initialized_.store(state);
        log_.debug("initialization state changed", redlog::field("initialized", state));
    }

    /**
     * @brief Check if debug mode is enabled
     */
    bool is_debug_mode() const {
        if constexpr (std::is_same_v<ConfigType, tracer_config_base>) {
            return config_.debug_mode;
        } else {
            // Try to access debug_mode if it exists
            if constexpr (requires { config_.debug_mode; }) {
                return config_.debug_mode;
            }
        }
        return false;
    }

    /**
     * @brief Get output file path
     */
    std::string get_output_file() const {
        if constexpr (std::is_same_v<ConfigType, tracer_config_base>) {
            return config_.output_file;
        } else {
            // Try to access output_file if it exists
            if constexpr (requires { config_.output_file; }) {
                return config_.output_file;
            }
        }
        return "output.dat";
    }

    /**
     * @brief Utility function to format numbers with thousands separators
     */
    static std::string format_number(uint64_t number) {
        std::string result = std::to_string(number);
        std::string formatted;
        int count = 0;
        for (int i = result.length() - 1; i >= 0; --i) {
            if (count && count % 3 == 0) {
                formatted = ',' + formatted;
            }
            formatted = result[i] + formatted;
            count++;
        }
        return formatted;
    }
};

} // namespace w1::framework