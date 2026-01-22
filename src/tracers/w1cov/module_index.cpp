#include "module_index.hpp"

namespace w1cov {

module_index::module_index(coverage_config config) : config_(std::move(config)) {}

void module_index::configure(const w1::runtime::module_catalog& modules) {
  modules_ = &modules;
  {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    modules_by_id_.clear();
    module_map_.clear();
  }
  seed_from_registry();
}

void module_index::seed_from_registry() {
  if (!modules_) {
    return;
  }

  auto list = modules_->list_modules();

  size_t traced = 0;
  {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    modules_by_id_.reserve(list.size());
    module_map_.reserve(list.size());

    for (const auto& module : list) {
      if (!should_trace_module(module)) {
        continue;
      }

      const uint64_t base = module.base_address;
      const std::string_view identity = module_identity_view(module);

      auto it = module_map_.find(base);
      if (it != module_map_.end() && it->second.identity == identity && it->second.size == module.size) {
        continue;
      }

      const uint16_t id = register_module_locked(module);
      module_map_[base] = module_entry{id, std::string(identity), module.size};
      traced += 1;
    }
  }

  log_.inf(
      "module index configured", redlog::field("modules", list.size()), redlog::field("traced", traced)
  );
}

std::optional<w1::core::module_lookup<uint16_t>> module_index::find_module(uint64_t address) const {
  if (!modules_ || address == 0) {
    return std::nullopt;
  }

  const auto* module = modules_->find_containing(address);
  if (!module || !should_trace_module(*module)) {
    return std::nullopt;
  }

  const uint64_t version = modules_->version();
  const uint64_t base = module->base_address;
  const uint64_t end = module->base_address + module->size;
  const std::string_view identity = module_identity_view(*module);

  {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = module_map_.find(base);
    if (it != module_map_.end() && it->second.identity == identity && it->second.size == module->size) {
      return w1::core::module_lookup<uint16_t>{it->second.id, base, end, version};
    }
  }

  std::unique_lock<std::shared_mutex> lock(mutex_);
  auto it = module_map_.find(base);
  if (it != module_map_.end() && it->second.identity == identity && it->second.size == module->size) {
    return w1::core::module_lookup<uint16_t>{it->second.id, base, end, version};
  }

  uint16_t id = register_module_locked(*module);
  module_map_[base] = module_entry{id, std::string(identity), module->size};
  return w1::core::module_lookup<uint16_t>{id, base, end, version};
}

std::vector<w1::runtime::module_info> module_index::snapshot_modules() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return modules_by_id_;
}

size_t module_index::tracked_module_count() const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return modules_by_id_.size();
}

uint64_t module_index::registry_version() const {
  return modules_ ? modules_->version() : 0;
}

bool module_index::should_trace_module(const w1::runtime::module_info& module) const {
  return config_.instrumentation.should_instrument(module);
}

std::string_view module_index::module_identity_view(const w1::runtime::module_info& module) const {
  if (!module.path.empty()) {
    return module.path;
  }
  return module.name;
}

uint16_t module_index::register_module_locked(const w1::runtime::module_info& module) const {
  modules_by_id_.push_back(module);
  return static_cast<uint16_t>(modules_by_id_.size() - 1);
}

} // namespace w1cov
