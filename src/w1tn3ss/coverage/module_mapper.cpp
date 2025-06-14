#include "module_mapper.hpp"
#include "coverage_data.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>

// qbdi includes
#include <QBDI.h>

namespace w1::coverage {

module_mapper::module_mapper(coverage_collector& collector)
    : log_(redlog::get_logger("w1tn3ss.module_mapper")),
      collector_(collector),
      exclude_system_(true) {
    log_.debug("module mapper initialized");
}

module_mapper::~module_mapper() {
    log_.debug("module mapper destroyed",
               redlog::field("total_regions", regions_.size()));
}

bool module_mapper::discover_process_modules() {
    log_.info("discovering process modules");
    
    // clear existing regions
    regions_.clear();
    
    bool success = false;
    
#ifdef __APPLE__
    success = discover_modules_darwin();
#elif defined(__linux__)
    success = discover_modules_linux();
#else
    success = discover_modules_unix();
#endif
    
    if (success) {
        log_.info("module discovery completed",
                  redlog::field("total_regions", regions_.size()),
                  redlog::field("executable_regions", get_executable_count()));
    } else {
        log_.error("module discovery failed");
    }
    
    return success;
}

bool module_mapper::discover_qbdi_modules() {
    log_.info("discovering modules via qbdi");
    
    try {
        // use qbdi to get current process memory maps
        std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps();
        
        log_.debug("qbdi returned memory maps",
                   redlog::field("count", maps.size()));
        
        return convert_qbdi_memory_maps(maps);
        
    } catch (const std::exception& e) {
        log_.error("qbdi module discovery failed",
                   redlog::field("error", e.what()));
        return false;
    }
}

size_t module_mapper::register_discovered_modules() {
    log_.info("registering discovered modules with coverage collector");
    
    size_t registered_count = 0;
    
    for (const auto& region : regions_) {
        if (!should_include_module(region)) {
            continue;
        }
        
        uint16_t module_id = collector_.add_module(
            region.name, 
            region.start, 
            region.end
        );
        
        if (module_id != UINT16_MAX) {
            registered_count++;
            log_.verbose("module registered",
                        redlog::field("id", module_id),
                        redlog::field("name", region.name),
                        redlog::field("size", region.size()));
        }
    }
    
    log_.info("module registration completed",
              redlog::field("registered_count", registered_count),
              redlog::field("total_regions", regions_.size()));
    
    return registered_count;
}

const memory_region* module_mapper::find_region_by_address(uint64_t address) const {
    for (const auto& region : regions_) {
        if (region.contains(address)) {
            return &region;
        }
    }
    return nullptr;
}

std::vector<memory_region> module_mapper::get_executable_regions() const {
    std::vector<memory_region> executable_regions;
    std::copy_if(regions_.begin(), regions_.end(),
                 std::back_inserter(executable_regions),
                 [](const memory_region& r) { return r.is_executable; });
    return executable_regions;
}

std::vector<memory_region> module_mapper::get_user_modules() const {
    std::vector<memory_region> user_modules;
    std::copy_if(regions_.begin(), regions_.end(),
                 std::back_inserter(user_modules),
                 [this](const memory_region& r) { 
                     return r.is_executable && !is_system_module(r.name); 
                 });
    return user_modules;
}

void module_mapper::add_target_module_pattern(const std::string& pattern) {
    target_patterns_.push_back(pattern);
    log_.debug("added target module pattern",
               redlog::field("pattern", pattern));
}

void module_mapper::clear_target_patterns() {
    target_patterns_.clear();
    log_.debug("cleared target module patterns");
}

size_t module_mapper::get_executable_count() const {
    return std::count_if(regions_.begin(), regions_.end(),
                        [](const memory_region& r) { return r.is_executable; });
}

size_t module_mapper::get_user_module_count() const {
    return std::count_if(regions_.begin(), regions_.end(),
                        [this](const memory_region& r) { 
                            return r.is_executable && !is_system_module(r.name); 
                        });
}

bool module_mapper::discover_modules_darwin() {
    log_.debug("using darwin-specific module discovery");
    
    // for now, fallback to qbdi method
    return discover_qbdi_modules();
}

bool module_mapper::discover_modules_linux() {
    log_.debug("using linux-specific module discovery via /proc/self/maps");
    
    std::ifstream maps_file("/proc/self/maps");
    if (!maps_file) {
        log_.warn("could not open /proc/self/maps, falling back to qbdi");
        return discover_qbdi_modules();
    }
    
    std::string line;
    while (std::getline(maps_file, line)) {
        // parse line format: address perms offset dev inode pathname
        std::istringstream iss(line);
        std::string address_range, perms, offset, dev, inode, pathname;
        
        if (!(iss >> address_range >> perms >> offset >> dev >> inode)) {
            continue;
        }
        
        // get optional pathname
        std::getline(iss, pathname);
        if (!pathname.empty() && pathname[0] == ' ') {
            pathname = pathname.substr(1); // remove leading space
        }
        
        // parse address range
        size_t dash_pos = address_range.find('-');
        if (dash_pos == std::string::npos) {
            continue;
        }
        
        uint64_t start = std::stoull(address_range.substr(0, dash_pos), nullptr, 16);
        uint64_t end = std::stoull(address_range.substr(dash_pos + 1), nullptr, 16);
        
        bool is_executable = (perms.length() > 2 && perms[2] == 'x');
        
        if (pathname.empty()) {
            pathname = "[anonymous]";
        }
        
        regions_.emplace_back(start, end, pathname, perms, is_executable);
    }
    
    return true;
}

bool module_mapper::discover_modules_unix() {
    log_.debug("using generic unix module discovery");
    
    // fallback to qbdi method for generic unix
    return discover_qbdi_modules();
}

bool module_mapper::is_system_module(const std::string& path) const {
    // heuristics for system modules/libraries
    if (path.empty() || path == "[anonymous]" || path.find("[") == 0) {
        return true; // anonymous mappings are usually system
    }
    
    return path.find("/System/") != std::string::npos ||
           path.find("/usr/lib/") != std::string::npos ||
           path.find("/usr/local/lib/") != std::string::npos ||
           path.find("/lib/") == 0 ||
           path.find("/lib64/") == 0 ||
           path.find("libsystem_") != std::string::npos ||
           path.find("libc.so") != std::string::npos ||
           path.find("libc++") != std::string::npos ||
           path.find("libdyld") != std::string::npos ||
           path.find("ld-linux") != std::string::npos;
}

bool module_mapper::matches_target_pattern(const std::string& path) const {
    if (target_patterns_.empty()) {
        return true; // no patterns means include all
    }
    
    for (const auto& pattern : target_patterns_) {
        try {
            std::regex pattern_regex(pattern);
            if (std::regex_search(path, pattern_regex)) {
                return true;
            }
        } catch (const std::exception& e) {
            log_.warn("invalid regex pattern",
                     redlog::field("pattern", pattern),
                     redlog::field("error", e.what()));
        }
    }
    
    return false;
}

bool module_mapper::should_include_module(const memory_region& region) const {
    // only include executable regions
    if (!region.is_executable) {
        return false;
    }
    
    // exclude system modules if configured
    if (exclude_system_ && is_system_module(region.name)) {
        return false;
    }
    
    // check target patterns
    if (!matches_target_pattern(region.name)) {
        return false;
    }
    
    return true;
}

std::string module_mapper::parse_permissions(const std::string& perm_str) const {
    // normalize permission string format
    return perm_str;
}

bool module_mapper::convert_qbdi_memory_maps(const std::vector<QBDI::MemoryMap>& maps) {
    regions_.clear();
    
    for (const auto& map : maps) {
        bool is_executable = (map.permission & QBDI::PF_EXEC) != 0;
        
        std::string perm_str;
        if (map.permission & QBDI::PF_READ) perm_str += "r";
        else perm_str += "-";
        if (map.permission & QBDI::PF_WRITE) perm_str += "w";
        else perm_str += "-";
        if (map.permission & QBDI::PF_EXEC) perm_str += "x";
        else perm_str += "-";
        
        std::string name = !map.name.empty() ? map.name : std::string("[unknown]");
        
        regions_.emplace_back(
            static_cast<uint64_t>(map.range.start()),
            static_cast<uint64_t>(map.range.end()),
            name,
            perm_str,
            is_executable
        );
    }
    
    log_.debug("converted qbdi memory maps",
               redlog::field("count", regions_.size()));
    
    return true;
}

} // namespace w1::coverage