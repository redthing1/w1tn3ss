#include "coverage_module_tracker.hpp"

namespace w1cov {

coverage_module_tracker::coverage_module_tracker(const coverage_config& config) : config_(config) {}

void coverage_module_tracker::initialize(const w1::runtime::module_registry& modules, coverage_collector& collector) {
  collector_ = &collector;
  module_map_.clear();

  auto list = modules.list_modules();
  module_map_.reserve(list.size());

  size_t traced = 0;
  for (const auto& module : list) {
    if (!should_trace_module(module)) {
      continue;
    }

    uint16_t module_id = collector_->add_module(module);
    module_map_[module.base_address] = module_id;
    traced += 1;
  }

  log_.inf(
      "coverage module tracker initialized", redlog::field("modules", list.size()),
      redlog::field("traced", traced)
  );
}

bool coverage_module_tracker::should_trace_module(const w1::runtime::module_info& module) const {
  return config_.instrumentation.should_instrument(module);
}

uint16_t coverage_module_tracker::ensure_module_registered(const w1::runtime::module_info& module) const {
  auto it = module_map_.find(module.base_address);
  if (it != module_map_.end()) {
    return it->second;
  }

  if (!collector_) {
    log_.err("collector unavailable while registering module");
    return 0;
  }

  uint16_t module_id = collector_->add_module(module);
  module_map_[module.base_address] = module_id;
  return module_id;
}

} // namespace w1cov
