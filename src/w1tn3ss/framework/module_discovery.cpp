/**
 * @file module_discovery.cpp
 * @brief Simplified cross-platform module discovery implementation
 */

#include "module_discovery.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <sys/types.h>
#include <sys/mman.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#endif

namespace w1::framework {

// === Module Discovery Implementation ===

bool module_discovery::discover_qbdi_modules() {
    log_.debug("qbdi-based module discovery not yet implemented - falling back to process-based");
    return discover_process_modules();
}

bool module_discovery::discover_process_modules() {
    log_.debug("attempting process-based module discovery");
    
    regions_.clear();
    
#ifdef __APPLE__
    return discover_modules_macos();
#elif defined(__linux__)
    return discover_modules_linux();
#elif defined(_WIN32)
    return discover_modules_windows();
#else
    log_.error("process module discovery not implemented for this platform");
    return false;
#endif
}

std::vector<memory_region> module_discovery::get_user_modules() const {
    std::vector<memory_region> user_modules;
    
    for (const auto& region : regions_) {
        if (!region.is_system_module && region.is_executable) {
            // Check against target patterns if specified
            if (!config_.target_patterns.empty()) {
                bool matches_pattern = false;
                for (const auto& pattern : config_.target_patterns) {
                    if (region.name.find(pattern) != std::string::npos ||
                        region.path.find(pattern) != std::string::npos) {
                        matches_pattern = true;
                        break;
                    }
                }
                if (!matches_pattern) continue;
            }
            
            user_modules.push_back(region);
        }
    }
    
    return user_modules;
}

std::vector<memory_region> module_discovery::get_executable_regions() const {
    std::vector<memory_region> executable_regions;
    
    for (const auto& region : regions_) {
        if (region.is_executable) {
            executable_regions.push_back(region);
        }
    }
    
    return executable_regions;
}

void module_discovery::add_target_pattern(const std::string& pattern) {
    config_.target_patterns.push_back(pattern);
    log_.debug("added target pattern", redlog::field("pattern", pattern));
}

void module_discovery::set_exclude_system_modules(bool exclude) {
    config_.exclude_system_modules = exclude;
    log_.debug("system module exclusion set", redlog::field("exclude", exclude));
}

size_t module_discovery::get_executable_count() const {
    return std::count_if(regions_.begin(), regions_.end(),
                        [](const memory_region& r) { return r.is_executable; });
}

size_t module_discovery::get_user_module_count() const {
    return std::count_if(regions_.begin(), regions_.end(),
                        [](const memory_region& r) { 
                            return !r.is_system_module && r.is_executable; 
                        });
}

void module_discovery::log_memory_layout_summary() const {
    log_.info("memory layout summary",
             redlog::field("total_regions", regions_.size()),
             redlog::field("executable_regions", get_executable_count()),
             redlog::field("user_modules", get_user_module_count()));
}

void module_discovery::log_discovered_modules() const {
    for (const auto& region : regions_) {
        if (region.is_executable) {
            log_.debug("discovered executable module",
                      redlog::field("name", region.name),
                      redlog::field("path", region.path),
                      redlog::field("start", region.start),
                      redlog::field("size", region.size()),
                      redlog::field("system", region.is_system_module));
        }
    }
}

// === Platform-Specific Implementations ===

#ifdef __APPLE__
bool module_discovery::discover_modules_macos() {
    log_.debug("using macos dyld-based module discovery");
    
    uint32_t image_count = _dyld_image_count();
    
    for (uint32_t i = 0; i < image_count; i++) {
        const char* image_name = _dyld_get_image_name(i);
        const struct mach_header* header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        
        if (!image_name || !header) continue;
        
        memory_region region;
        region.path = image_name;
        region.name = extract_module_name(image_name);
        region.is_system_module = is_system_module_name(region.name);
        
        // Parse mach-o header to get text segment
        if (header->magic == MH_MAGIC_64) {
            const struct mach_header_64* header64 = (const struct mach_header_64*)header;
            const struct load_command* cmd = (const struct load_command*)(header64 + 1);
            
            for (uint32_t j = 0; j < header64->ncmds; j++) {
                if (cmd->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64* seg = (const struct segment_command_64*)cmd;
                    
                    if (strcmp(seg->segname, SEG_TEXT) == 0) {
                        region.start = seg->vmaddr + slide;
                        region.end = region.start + seg->vmsize;
                        region.is_executable = (seg->initprot & VM_PROT_EXECUTE) != 0;
                        region.permissions = seg->initprot;
                        break;
                    }
                }
                cmd = (const struct load_command*)((char*)cmd + cmd->cmdsize);
            }
        }
        
        if (region.size() > 0) {
            regions_.push_back(region);
            
            if (config_.log_verbose) {
                log_.debug("discovered macos module",
                          redlog::field("name", region.name),
                          redlog::field("start", region.start),
                          redlog::field("size", region.size()));
            }
        }
    }
    
    log_.info("macos module discovery completed", redlog::field("modules", regions_.size()));
    invalidate_cache();
    return !regions_.empty();
}
#else
bool module_discovery::discover_modules_macos() {
    log_.error("macOS module discovery not available on this platform");
    return false;
}
#endif

#ifdef __linux__
bool module_discovery::discover_modules_linux() {
    log_.debug("using linux /proc/self/maps module discovery");
    
    std::ifstream maps_file("/proc/self/maps");
    if (!maps_file.is_open()) {
        log_.error("failed to open /proc/self/maps");
        return false;
    }
    
    std::string line;
    while (std::getline(maps_file, line)) {
        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode, pathname;
        
        if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) {
            continue;
        }
        
        // Get pathname (may contain spaces)
        std::getline(iss, pathname);
        if (!pathname.empty() && pathname[0] == ' ') {
            pathname = pathname.substr(1); // Remove leading space
        }
        
        // Parse address range
        size_t dash_pos = addr_range.find('-');
        if (dash_pos == std::string::npos) continue;
        
        uint64_t start = std::stoull(addr_range.substr(0, dash_pos), nullptr, 16);
        uint64_t end = std::stoull(addr_range.substr(dash_pos + 1), nullptr, 16);
        
        // Only process executable regions with a pathname
        if (perms.size() >= 3 && perms[2] == 'x' && !pathname.empty() && pathname[0] == '/') {
            memory_region region;
            region.start = start;
            region.end = end;
            region.path = pathname;
            region.name = extract_module_name(pathname);
            region.is_executable = true;
            region.is_system_module = is_system_module_name(region.name);
            region.permissions = parse_linux_permissions(perms);
            
            regions_.push_back(region);
            
            if (config_.log_verbose) {
                log_.debug("discovered linux module",
                          redlog::field("name", region.name),
                          redlog::field("start", region.start),
                          redlog::field("size", region.size()));
            }
        }
    }
    
    log_.info("linux module discovery completed", redlog::field("modules", regions_.size()));
    invalidate_cache();
    return !regions_.empty();
}

uint32_t module_discovery::parse_linux_permissions(const std::string& perms) const {
    uint32_t perm = 0;
    if (perms.size() >= 4) {
        if (perms[0] == 'r') perm |= 0x1;
        if (perms[1] == 'w') perm |= 0x2;
        if (perms[2] == 'x') perm |= 0x4;
    }
    return perm;
}
#else
bool module_discovery::discover_modules_linux() {
    log_.error("Linux module discovery not available on this platform");
    return false;
}

uint32_t module_discovery::parse_linux_permissions(const std::string& perms) const {
    return 0;
}
#endif

#ifdef _WIN32
bool module_discovery::discover_modules_windows() {
    log_.debug("using windows psapi module discovery");
    
    HANDLE process = GetCurrentProcess();
    HMODULE modules[1024];
    DWORD bytes_needed;
    
    if (!EnumProcessModules(process, modules, sizeof(modules), &bytes_needed)) {
        log_.error("failed to enumerate process modules");
        return false;
    }
    
    DWORD module_count = bytes_needed / sizeof(HMODULE);
    
    for (DWORD i = 0; i < module_count; i++) {
        MODULEINFO module_info;
        char module_name[MAX_PATH];
        char module_path[MAX_PATH];
        
        if (GetModuleInformation(process, modules[i], &module_info, sizeof(module_info)) &&
            GetModuleBaseNameA(process, modules[i], module_name, sizeof(module_name)) &&
            GetModuleFileNameExA(process, modules[i], module_path, sizeof(module_path))) {
            
            memory_region region;
            region.start = reinterpret_cast<uint64_t>(module_info.lpBaseOfDll);
            region.end = region.start + module_info.SizeOfImage;
            region.path = module_path;
            region.name = module_name;
            region.is_executable = true; // Assume all loaded modules are executable
            region.is_system_module = is_system_module_name(region.name);
            region.permissions = 0; // TODO: Get actual permissions
            
            regions_.push_back(region);
            
            if (config_.log_verbose) {
                log_.debug("discovered windows module",
                          redlog::field("name", region.name),
                          redlog::field("start", region.start),
                          redlog::field("size", region.size()));
            }
        }
    }
    
    log_.info("windows module discovery completed", redlog::field("modules", regions_.size()));
    invalidate_cache();
    return !regions_.empty();
}
#else
bool module_discovery::discover_modules_windows() {
    log_.error("Windows module discovery not available on this platform");
    return false;
}
#endif

// === Utility Methods ===

std::string module_discovery::extract_module_name(const std::string& path) const {
    size_t last_slash = path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        return path.substr(last_slash + 1);
    }
    return path;
}

bool module_discovery::is_system_module_name(const std::string& name) const {
    // Common system module patterns across platforms
    static const std::vector<std::string> system_patterns = {
        "libc", "libSystem", "libdyld", "libpthread", "libm", "libdl",
        "ntdll", "kernel32", "user32", "advapi32", "msvcrt",
        "ld-linux", "libresolv", "librt", "libgcc_s", "libstdc++",
        "CoreFoundation", "Foundation", "AppKit", "IOKit"
    };
    
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    for (const auto& pattern : system_patterns) {
        if (lower_name.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void module_discovery::invalidate_cache() const {
    cache_valid_ = false;
    address_cache_.clear();
}

// === Factory Functions ===

std::unique_ptr<module_discovery> create_module_discovery(bool exclude_system, bool verbose_logging) {
    module_discovery_config config;
    config.exclude_system_modules = exclude_system;
    config.log_verbose = verbose_logging;
    
    return std::make_unique<module_discovery>(config);
}

} // namespace w1::framework