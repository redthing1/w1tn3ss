#include "coverage_module_tracker.hpp"
#include <algorithm>

namespace w1cov {

coverage_module_tracker::coverage_module_tracker(const coverage_config& config) 
    : config_(config), index_(std::vector<w1::util::module_info>{}), collector_(nullptr) {}

void coverage_module_tracker::initialize(coverage_collector& collector) {
    log_.vrb("initializing coverage module tracker");
    
    collector_ = &collector;
    
    // scan all executable modules
    auto all_modules = scanner_.scan_executable_modules();
    
    // filter modules that should be traced
    std::vector<w1::util::module_info> traced_modules;
    traced_modules.reserve(all_modules.size() / 2); // estimate
    
    for (const auto& mod : all_modules) {
        if (should_trace_module(mod)) {
            traced_modules.push_back(mod);
        }
    }
    
    // register modules with collector and build mapping
    base_to_module_id_.clear();
    base_to_module_id_.reserve(traced_modules.size());
    
    for (const auto& mod : traced_modules) {
        uint16_t module_id = collector_->add_module(mod);
        base_to_module_id_[mod.base_address] = module_id;
        
        log_.dbg("registered traced module", 
                 redlog::field("module_name", mod.name),
                 redlog::field("module_id", module_id),
                 redlog::field("base_address", "0x%08x", mod.base_address));
    }
    
    // build fast lookup index
    index_ = w1::util::module_range_index(std::move(traced_modules));
    
    log_.inf("module tracker initialization complete", 
             redlog::field("total_modules", all_modules.size()),
             redlog::field("traced_modules", traced_module_count()));
}

size_t coverage_module_tracker::traced_module_count() const {
    std::shared_lock<std::shared_mutex> lock(index_mutex_);
    return index_.size();
}

bool coverage_module_tracker::should_trace_module(const w1::util::module_info& mod) const {
    // unknown modules are never traced
    if (mod.type == w1::util::module_type::UNKNOWN) {
        return false;
    }
    
    // apply module name filter if specified
    if (!config_.module_filter.empty()) {
        for (const auto& filter_name : config_.module_filter) {
            if (mod.name.find(filter_name) != std::string::npos) {
                return true;
            }
        }
        return false; // not in filter list
    }
    
    // exclude system modules if configured
    if (config_.exclude_system_modules && mod.is_system_library) {
        return false;
    }
    
    // default: trace all non-system modules
    return true;
}

void coverage_module_tracker::rebuild_index_from_modules(std::vector<w1::util::module_info> modules) {
    // filter modules for tracing
    std::vector<w1::util::module_info> traced_modules;
    traced_modules.reserve(modules.size() / 2);
    
    std::copy_if(modules.begin(), modules.end(), std::back_inserter(traced_modules),
                 [this](const w1::util::module_info& mod) {
                     return should_trace_module(mod);
                 });
    
    // rebuild index
    index_ = w1::util::module_range_index(std::move(traced_modules));
}

std::unordered_set<QBDI::rword> coverage_module_tracker::get_known_module_bases() const {
    std::shared_lock<std::shared_mutex> lock(index_mutex_);
    
    std::unordered_set<QBDI::rword> known_bases;
    known_bases.reserve(base_to_module_id_.size());
    
    for (const auto& pair : base_to_module_id_) {
        known_bases.insert(pair.first);
    }
    
    return known_bases;
}

} // namespace w1cov