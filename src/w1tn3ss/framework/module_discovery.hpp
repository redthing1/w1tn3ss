/**
 * @file module_discovery.hpp
 * @brief Generic cross-platform module discovery utilities for w1tn3ss framework
 * 
 * This component provides reusable module enumeration, filtering, and management
 * functionality that can be used by any tracer implementation.
 */

#pragma once

#include <redlog/redlog.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

// Forward declarations for QBDI types
namespace QBDI {
struct MemoryMap;
}

namespace w1::framework {

/**
 * @brief Generic memory region representation
 */
struct memory_region {
    uint64_t start = 0;
    uint64_t end = 0;
    std::string name;
    std::string path;
    uint32_t permissions = 0;
    bool is_executable = false;
    bool is_system_module = false;

    memory_region() = default;
    memory_region(uint64_t s, uint64_t e, const std::string& n, const std::string& p, 
                  uint32_t perm, bool exec)
        : start(s), end(e), name(n), path(p), permissions(perm), is_executable(exec) {}

    uint64_t size() const { return end - start; }
    bool contains(uint64_t addr) const { return addr >= start && addr < end; }
    
    // Get just the filename from the path
    std::string filename() const {
        size_t pos = path.find_last_of("/\\");
        return pos != std::string::npos ? path.substr(pos + 1) : path;
    }
};

/**
 * @brief Configuration for module discovery
 */
struct module_discovery_config {
    bool exclude_system_modules = true;
    bool log_verbose = false;
    std::vector<std::string> target_patterns;
    
    // Platform-specific system module patterns
    std::vector<std::string> system_patterns;
};

/**
 * @brief Cross-platform module discovery and filtering utility
 * 
 * This class provides a generic interface for discovering and filtering
 * executable modules in the current process. It can be used by any tracer
 * that needs module information.
 */
class module_discovery {
public:
    explicit module_discovery(const module_discovery_config& config = {})
        : log_(redlog::get_logger("w1tn3ss.module_discovery")), config_(config) {}
    ~module_discovery() = default;

    // Core discovery methods
    bool discover_process_modules();
    bool discover_qbdi_modules();
    void clear_discovered_modules();

    // Query methods
    const memory_region* find_region_by_address(uint64_t address) const;
    std::vector<memory_region> get_all_regions() const { return regions_; }
    std::vector<memory_region> get_executable_regions() const;
    std::vector<memory_region> get_user_modules() const;
    
    // Configuration
    void set_exclude_system_modules(bool exclude);
    void add_target_pattern(const std::string& pattern);
    void clear_target_patterns();
    void set_verbose_logging(bool verbose);

    // Statistics
    size_t get_total_regions() const { return regions_.size(); }
    size_t get_executable_count() const;
    size_t get_user_module_count() const;
    
    // Debugging
    void log_memory_layout_summary() const;
    void log_discovered_modules() const;

private:
    redlog::logger log_;
    module_discovery_config config_;
    std::vector<memory_region> regions_;
    
    // Efficient address-to-region mapping for hot path lookups
    mutable std::unordered_map<uint64_t, const memory_region*> address_cache_;
    mutable bool cache_valid_ = false;

    // Platform-specific discovery implementations
    bool discover_modules_macos();
    bool discover_modules_linux();
    bool discover_modules_windows();
    
    // Utility methods
    void invalidate_cache() const;
    std::string extract_module_name(const std::string& path) const;
    bool is_system_module_name(const std::string& name) const;
    uint32_t parse_linux_permissions(const std::string& perms) const;
};

/**
 * @brief Factory function for creating module discovery with platform defaults
 */
std::unique_ptr<module_discovery> create_module_discovery(bool exclude_system = true, 
                                                         bool verbose = false);

} // namespace w1::framework