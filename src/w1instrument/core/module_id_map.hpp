#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "w1instrument/core/module_cache.hpp"
#include "w1runtime/module_catalog.hpp"

namespace w1::core {

// PolicyT must provide:
//  - bool include(const w1::runtime::module_info&) const
//  - std::string_view identity(const w1::runtime::module_info&) const
// The identity is used to keep module IDs stable across refreshes.
template <typename PolicyT, typename IdT = uint16_t>
class module_id_map {
public:
  explicit module_id_map(PolicyT policy = {}) : policy_(std::move(policy)) {}

  void configure(const runtime::module_catalog& modules) {
    modules_ = &modules;
    {
      std::unique_lock<std::shared_mutex> lock(mutex_);
      modules_by_id_.clear();
      module_map_.clear();
    }
    seed_from_catalog();
  }

  std::optional<module_lookup<IdT>> find(uint64_t address) const {
    if (!modules_ || address == 0) {
      return std::nullopt;
    }

    const auto* module = modules_->find_containing(address);
    if (!module || !policy_.include(*module)) {
      return std::nullopt;
    }

    const uint64_t version = modules_->version();
    const uint64_t base = module->base_address;
    const uint64_t end = module->base_address + module->size;
    const std::string_view identity = policy_.identity(*module);

    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = module_map_.find(base);
      if (it != module_map_.end() && it->second.identity == identity && it->second.size == module->size) {
        return module_lookup<IdT>{it->second.id, base, end, version};
      }
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = module_map_.find(base);
    if (it != module_map_.end() && it->second.identity == identity && it->second.size == module->size) {
      return module_lookup<IdT>{it->second.id, base, end, version};
    }

    IdT id = register_module_locked(*module);
    module_map_[base] = module_entry{id, std::string(identity), module->size};
    return module_lookup<IdT>{id, base, end, version};
  }

  uint64_t registry_version() const { return modules_ ? modules_->version() : 0; }

  std::vector<runtime::module_info> snapshot_modules() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return modules_by_id_;
  }

  size_t tracked_module_count() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return modules_by_id_.size();
  }

  PolicyT& policy() { return policy_; }
  const PolicyT& policy() const { return policy_; }

private:
  struct module_entry {
    IdT id{};
    std::string identity;
    uint64_t size = 0;
  };

  void seed_from_catalog() {
    if (!modules_) {
      return;
    }

    auto list = modules_->list_modules();

    std::unique_lock<std::shared_mutex> lock(mutex_);
    modules_by_id_.reserve(list.size());
    module_map_.reserve(list.size());

    for (const auto& module : list) {
      if (!policy_.include(module)) {
        continue;
      }

      const uint64_t base = module.base_address;
      const std::string_view identity = policy_.identity(module);

      auto it = module_map_.find(base);
      if (it != module_map_.end() && it->second.identity == identity && it->second.size == module.size) {
        continue;
      }

      const IdT id = register_module_locked(module);
      module_map_[base] = module_entry{id, std::string(identity), module.size};
    }
  }

  IdT register_module_locked(const runtime::module_info& module) const {
    modules_by_id_.push_back(module);
    return static_cast<IdT>(modules_by_id_.size() - 1);
  }

  PolicyT policy_{};
  const runtime::module_catalog* modules_ = nullptr;

  mutable std::shared_mutex mutex_{};
  mutable std::vector<runtime::module_info> modules_by_id_{};
  mutable std::unordered_map<uint64_t, module_entry> module_map_{};
};

} // namespace w1::core
