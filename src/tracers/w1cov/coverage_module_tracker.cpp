#include "coverage_module_tracker.hpp"
#include <algorithm>

namespace w1cov {

coverage_module_tracker::coverage_module_tracker(const coverage_config& config)
    : config_(config), collector_(nullptr) {}

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
  {
    std::unique_lock<std::shared_mutex> lock(map_mutex_);
    module_map_.clear();
    module_map_.reserve(traced_modules.size());

    for (const auto& mod : traced_modules) {
      uint16_t module_id = collector_->add_module(mod);
      module_map_[mod.base_address] = module_id;

      log_.ped(
          "registered traced module", redlog::field("module_name", mod.name), redlog::field("module_id", module_id),
          redlog::field("base_address", "0x%08x", mod.base_address)
      );
    }
  }

  // build fast lookup index with traced modules
  index_.rebuild_from_modules(std::move(traced_modules));

  log_.inf(
      "module tracker initialization complete", redlog::field("total_modules", all_modules.size()),
      redlog::field("traced_modules", traced_module_count())
  );
}

size_t coverage_module_tracker::traced_module_count() const { return index_.size(); }

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

  // include system modules only if configured
  if (mod.is_system_library && !config_.include_system_modules) {
    return false;
  }

  // default: trace all modules except system modules (unless include_system_modules is true)
  return true;
}

void coverage_module_tracker::rebuild_traced_modules() {
  // scan all current modules
  auto all_modules = scanner_.scan_executable_modules();

  // filter modules for tracing
  std::vector<w1::util::module_info> traced_modules;
  traced_modules.reserve(all_modules.size() / 2);

  std::copy_if(
      all_modules.begin(), all_modules.end(), std::back_inserter(traced_modules),
      [this](const w1::util::module_info& mod) { return should_trace_module(mod); }
  );

  // rebuild index with filtered modules
  index_.rebuild_from_modules(std::move(traced_modules));
}

uint16_t coverage_module_tracker::ensure_module_registered(const w1::util::module_info& mod) {
  {
    std::shared_lock<std::shared_mutex> lock(map_mutex_);
    auto it = module_map_.find(mod.base_address);
    if (it != module_map_.end()) {
      return it->second;
    }
  }

  std::unique_lock<std::shared_mutex> lock(map_mutex_);

  auto it = module_map_.find(mod.base_address);
  if (it != module_map_.end()) {
    return it->second;
  }

  if (!collector_) {
    log_.err("collector unavailable during module registration");
    return 0;
  }

  uint16_t module_id = collector_->add_module(mod);
  module_map_[mod.base_address] = module_id;

  log_.ped(
      "added new traced module", redlog::field("module_name", mod.name), redlog::field("module_id", module_id),
      redlog::field("base_address", "0x%08x", mod.base_address)
  );

  return module_id;
}

} // namespace w1cov
