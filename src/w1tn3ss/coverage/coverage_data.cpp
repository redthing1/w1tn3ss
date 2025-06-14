#include "coverage_data.hpp"
#include <algorithm>
#include <fstream>
#include <filesystem>

namespace w1::coverage {

coverage_collector::coverage_collector() 
    : log_(redlog::get_logger("w1tn3ss.coverage")), 
      next_module_id_(0),
      exclude_system_(true),
      output_file_("coverage.drcov") {
    log_.debug("coverage collector initialized");
}

coverage_collector::~coverage_collector() {
    log_.info("coverage collector shutting down",
              redlog::field("blocks", get_total_blocks()),
              redlog::field("unique", get_unique_blocks()),
              redlog::field("modules", modules_.size()));
}

uint16_t coverage_collector::add_module(const std::string& path, uint64_t base, uint64_t end, uint64_t entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // check if we should exclude system modules
    if (exclude_system_ && is_system_module(path)) {
        log_.verbose("excluding system module", redlog::field("path", path));
        return UINT16_MAX; // invalid module id
    }
    
    // check if module already exists
    for (const auto& module : modules_) {
        if (module.path == path && module.base_address == base) {
            log_.verbose("module already exists", 
                        redlog::field("path", path),
                        redlog::field("id", module.id));
            return module.id;
        }
    }
    
    uint16_t module_id = next_module_id_++;
    modules_.emplace_back(module_id, path, base, end, entry);
    
    // update address-to-module mapping for faster lookups
    for (uint64_t addr = base; addr < end; addr += 0x1000) { // page-aligned sampling
        address_to_module_[addr] = module_id;
    }
    
    log_.info("module added",
              redlog::field("id", module_id),
              redlog::field("path", path),
              redlog::field("base", base),
              redlog::field("size", end - base));
    
    return module_id;
}

const module_info* coverage_collector::find_module_by_address(uint64_t address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // try fast lookup first
    uint64_t page_addr = address & ~0xFFF; // align to page boundary
    auto it = address_to_module_.find(page_addr);
    if (it != address_to_module_.end()) {
        return find_module_by_id(it->second);
    }
    
    // fallback to linear search
    for (const auto& module : modules_) {
        if (module.contains_address(address)) {
            return &module;
        }
    }
    
    return nullptr;
}

const module_info* coverage_collector::find_module_by_id(uint16_t id) const {
    // note: caller should already hold mutex
    for (const auto& module : modules_) {
        if (module.id == id) {
            return &module;
        }
    }
    return nullptr;
}

void coverage_collector::record_basic_block(uint64_t address, uint16_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // find the module containing this address
    const module_info* module = find_module_by_address(address);
    if (!module) {
        // try to discover the module dynamically
        uint16_t module_id = find_or_create_module_for_address(address);
        if (module_id == UINT16_MAX) {
            return; // couldn't find/create module
        }
        module = find_module_by_id(module_id);
    }
    
    record_basic_block_with_module(address, size, module->id);
}

void coverage_collector::record_basic_block_with_module(uint64_t address, uint16_t size, uint16_t module_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // check if we've already covered this exact address
    if (covered_addresses_.find(address) != covered_addresses_.end()) {
        return; // already recorded
    }
    
    covered_addresses_.insert(address);
    basic_blocks_.emplace_back(address, size, module_id);
    
    log_.trace("basic block recorded",
               redlog::field("address", address),
               redlog::field("size", size),
               redlog::field("id", module_id));
}

size_t coverage_collector::get_total_blocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return basic_blocks_.size();
}

size_t coverage_collector::get_unique_blocks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return covered_addresses_.size();
}

std::unordered_map<uint16_t, size_t> coverage_collector::get_coverage_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::unordered_map<uint16_t, size_t> stats;
    for (const auto& block : basic_blocks_) {
        stats[block.module_id]++;
    }
    return stats;
}

drcov::coverage_data coverage_collector::export_drcov_data() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    log_.info("exporting coverage data to drcov format",
              redlog::field("modules", modules_.size()),
              redlog::field("blocks", basic_blocks_.size()),
              redlog::field("unique", covered_addresses_.size()));
    
    if (modules_.empty()) {
        log_.warn("no modules available for drcov export");
    }
    
    if (basic_blocks_.empty()) {
        log_.warn("no basic blocks collected for drcov export");
    }
    
    auto builder = drcov::builder()
        .set_flavor("w1cov")
        .set_module_version(drcov::module_table_version::v2);
    
    // add modules with validation
    size_t valid_modules = 0;
    size_t invalid_modules = 0;
    
    log_.debug("adding modules to drcov data");
    
    for (const auto& module : modules_) {
        try {
            // validate module data before adding
            if (module.base_address >= module.end_address) {
                log_.warn("invalid module address range detected",
                         redlog::field("id", module.id),
                         redlog::field("path", module.path),
                         redlog::field("base", module.base_address),
                         redlog::field("end", module.end_address));
                invalid_modules++;
                continue;
            }
            
            if (module.path.empty()) {
                log_.warn("module has empty path",
                         redlog::field("id", module.id),
                         redlog::field("base", module.base_address));
                invalid_modules++;
                continue;
            }
            
            builder.add_module(module.path, module.base_address, module.end_address, module.entry_point);
            valid_modules++;
            
            log_.trace("added module to drcov",
                      redlog::field("id", module.id),
                      redlog::field("path", module.path),
                      redlog::field("base", module.base_address),
                      redlog::field("end", module.end_address),
                      redlog::field("size", module.end_address - module.base_address));
            
        } catch (const std::exception& e) {
            log_.error("failed to add module to drcov builder",
                      redlog::field("id", module.id),
                      redlog::field("path", module.path),
                      redlog::field("error", e.what()));
            invalid_modules++;
        }
    }
    
    log_.debug("module processing completed",
               redlog::field("valid", valid_modules),
               redlog::field("invalid", invalid_modules));
    
    // add basic blocks with validation
    size_t valid_blocks = 0;
    size_t invalid_blocks = 0;
    size_t orphaned_blocks = 0;
    
    log_.debug("adding basic blocks to drcov data");
    
    for (const auto& block : basic_blocks_) {
        try {
            const module_info* module = find_module_by_id(block.module_id);
            if (!module) {
                log_.trace("basic block references unknown module",
                          redlog::field("id", block.module_id),
                          redlog::field("address", block.address));
                orphaned_blocks++;
                continue;
            }
            
            // validate block is within module bounds
            if (block.address < module->base_address || block.address >= module->end_address) {
                log_.warn("basic block address outside module bounds",
                         redlog::field("id", block.module_id),
                         redlog::field("address", block.address),
                         redlog::field("base", module->base_address),
                         redlog::field("end", module->end_address));
                invalid_blocks++;
                continue;
            }
            
            uint32_t offset = module->relative_offset(block.address);
            
            // validate offset calculation
            if (offset >= (module->end_address - module->base_address)) {
                log_.warn("calculated offset exceeds module size",
                         redlog::field("id", block.module_id),
                         redlog::field("offset", offset),
                         redlog::field("size", module->end_address - module->base_address));
                invalid_blocks++;
                continue;
            }
            
            builder.add_coverage(block.module_id, offset, block.size);
            valid_blocks++;
            
            log_.trace("added basic block to drcov",
                      redlog::field("id", block.module_id),
                      redlog::field("address", block.address),
                      redlog::field("offset", offset),
                      redlog::field("size", block.size));
            
        } catch (const std::exception& e) {
            log_.error("failed to add basic block to drcov builder",
                      redlog::field("id", block.module_id),
                      redlog::field("address", block.address),
                      redlog::field("error", e.what()));
            invalid_blocks++;
        }
    }
    
    log_.info("basic block processing completed",
              redlog::field("valid", valid_blocks),
              redlog::field("invalid", invalid_blocks),
              redlog::field("orphaned", orphaned_blocks));
    
    if (valid_blocks == 0 && !basic_blocks_.empty()) {
        log_.warn("no valid basic blocks were exported despite having collected data");
    }
    
    try {
        auto result = builder.build();
        
        log_.info("drcov data export completed successfully",
                  redlog::field("modules", valid_modules),
                  redlog::field("blocks", valid_blocks));
        
        return result;
        
    } catch (const std::exception& e) {
        log_.error("failed to build drcov data structure",
                  redlog::field("error", e.what()));
        throw; // re-throw to be handled by caller
    }
}

bool coverage_collector::write_drcov_file(const std::string& filepath) const {
    log_.info("writing coverage data to drcov file",
              redlog::field("filepath", filepath));
    
    // validate output directory exists
    std::filesystem::path file_path(filepath);
    auto parent_dir = file_path.parent_path();
    
    if (!parent_dir.empty()) {
        std::error_code fs_error;
        
        if (!std::filesystem::exists(parent_dir, fs_error)) {
            log_.warn("output directory does not exist, attempting to create",
                     redlog::field("directory", parent_dir.string()));
            
            if (!std::filesystem::create_directories(parent_dir, fs_error)) {
                log_.error("failed to create output directory",
                          redlog::field("directory", parent_dir.string()),
                          redlog::field("error", fs_error.message()));
                return false;
            }
            
            log_.debug("created output directory",
                      redlog::field("directory", parent_dir.string()));
        }
        
        // check directory permissions
        auto dir_status = std::filesystem::status(parent_dir, fs_error);
        if (fs_error) {
            log_.error("failed to check output directory status",
                      redlog::field("directory", parent_dir.string()),
                      redlog::field("error", fs_error.message()));
            return false;
        }
        
        if (!std::filesystem::is_directory(dir_status)) {
            log_.error("output path parent is not a directory",
                      redlog::field("path", parent_dir.string()));
            return false;
        }
    }
    
    // check if output file already exists
    std::error_code fs_error;
    bool file_exists = std::filesystem::exists(filepath, fs_error);
    if (fs_error) {
        log_.warn("failed to check if output file exists",
                 redlog::field("filepath", filepath),
                 redlog::field("error", fs_error.message()));
    } else if (file_exists) {
        auto file_size = std::filesystem::file_size(filepath, fs_error);
        log_.debug("output file already exists, will be overwritten",
                  redlog::field("filepath", filepath),
                  redlog::field("existing", fs_error ? 0 : file_size));
    }
    
    try {
        log_.debug("exporting coverage data to drcov format");
        auto coverage_data = export_drcov_data();
        
        log_.debug("writing drcov data to file",
                  redlog::field("filepath", filepath));
        
        drcov::write(filepath, coverage_data);
        
        // verify file was written successfully
        if (!std::filesystem::exists(filepath, fs_error)) {
            log_.error("drcov file was not created",
                      redlog::field("filepath", filepath));
            return false;
        }
        
        auto final_size = std::filesystem::file_size(filepath, fs_error);
        if (fs_error) {
            log_.warn("failed to get final file size",
                     redlog::field("filepath", filepath),
                     redlog::field("error", fs_error.message()));
        }
        
        log_.info("drcov file written successfully",
                  redlog::field("filepath", filepath),
                  redlog::field("bytes", fs_error ? 0 : final_size),
                  redlog::field("modules", modules_.size()),
                  redlog::field("blocks", basic_blocks_.size()),
                  redlog::field("unique", covered_addresses_.size()));
        
        return true;
        
    } catch (const std::exception& e) {
        log_.error("failed to write drcov file",
                   redlog::field("filepath", filepath),
                   redlog::field("error", e.what()),
                   redlog::field("exception_type", typeid(e).name()));
        
        // check if partial file was created and remove it
        std::error_code cleanup_error;
        if (std::filesystem::exists(filepath, cleanup_error) && !cleanup_error) {
            if (std::filesystem::remove(filepath, cleanup_error)) {
                log_.debug("removed incomplete drcov file",
                          redlog::field("filepath", filepath));
            } else {
                log_.warn("failed to remove incomplete drcov file",
                         redlog::field("filepath", filepath),
                         redlog::field("error", cleanup_error.message()));
            }
        }
        
        return false;
    }
}

bool coverage_collector::is_system_module(const std::string& path) const {
    // simple heuristic for system modules
    return path.find("/System/") != std::string::npos ||
           path.find("/usr/lib/") != std::string::npos ||
           path.find("/usr/local/lib/") != std::string::npos ||
           path.find("libsystem_") != std::string::npos ||
           path.find("libc++") != std::string::npos ||
           path.find("libdyld") != std::string::npos;
}

uint16_t coverage_collector::find_or_create_module_for_address(uint64_t address) {
    // this would normally use QBDI's getCurrentProcessMaps() to discover modules
    // for now, return invalid id to indicate we can't create modules dynamically
    log_.warn("attempted to create module for unknown address",
              redlog::field("address", address));
    return UINT16_MAX;
}

// global instance
static coverage_collector g_collector;

coverage_collector& get_global_collector() {
    return g_collector;
}

} // namespace w1::coverage