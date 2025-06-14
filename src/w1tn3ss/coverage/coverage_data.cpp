#include "coverage_data.hpp"
#include <algorithm>
#include <fstream>

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
              redlog::field("total_blocks", get_total_blocks()),
              redlog::field("unique_blocks", get_unique_blocks()),
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
               redlog::field("module_id", module_id));
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
    
    auto builder = drcov::builder()
        .set_flavor("w1cov")
        .set_module_version(drcov::module_table_version::v2);
    
    // add modules
    for (const auto& module : modules_) {
        builder.add_module(module.path, module.base_address, module.end_address, module.entry_point);
    }
    
    // add basic blocks
    for (const auto& block : basic_blocks_) {
        const module_info* module = find_module_by_id(block.module_id);
        if (module) {
            uint32_t offset = module->relative_offset(block.address);
            builder.add_coverage(block.module_id, offset, block.size);
        }
    }
    
    return builder.build();
}

bool coverage_collector::write_drcov_file(const std::string& filepath) const {
    try {
        auto coverage_data = export_drcov_data();
        drcov::write(filepath, coverage_data);
        
        log_.info("drcov file written",
                  redlog::field("filepath", filepath),
                  redlog::field("modules", modules_.size()),
                  redlog::field("basic_blocks", basic_blocks_.size()));
        
        return true;
    } catch (const std::exception& e) {
        log_.error("failed to write drcov file",
                   redlog::field("filepath", filepath),
                   redlog::field("error", e.what()));
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