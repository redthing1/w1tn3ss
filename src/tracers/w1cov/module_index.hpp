#pragma once

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <redlog.hpp>

#include "w1runtime/module_registry.hpp"

#include "coverage_config.hpp"

namespace w1cov {

class module_index {
public:
  explicit module_index(coverage_config config);

  void configure(const w1::runtime::module_registry& modules);

  std::optional<uint16_t> find_module_id(uint64_t address) const;

  std::vector<w1::runtime::module_info> snapshot_modules() const;
  size_t tracked_module_count() const;

private:
  struct module_entry {
    uint16_t id = 0;
    std::string identity;
    uint64_t size = 0;
  };

  void seed_from_registry();
  bool should_trace_module(const w1::runtime::module_info& module) const;
  std::string_view module_identity_view(const w1::runtime::module_info& module) const;
  uint16_t register_module_locked(const w1::runtime::module_info& module) const;

  coverage_config config_{};
  const w1::runtime::module_registry* modules_ = nullptr;

  mutable std::shared_mutex mutex_{};
  mutable std::vector<w1::runtime::module_info> modules_by_id_{};
  mutable std::unordered_map<uint64_t, module_entry> module_map_{};
  redlog::logger log_ = redlog::get_logger("w1cov.module_index");
};

} // namespace w1cov
