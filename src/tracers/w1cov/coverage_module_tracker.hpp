#pragma once

#include <cstdint>
#include <type_traits>
#include <unordered_map>

#include <redlog.hpp>

#include "w1tn3ss/runtime/module_registry.hpp"

#include "coverage_collector.hpp"
#include "coverage_config.hpp"

namespace w1cov {

class coverage_module_tracker {
public:
  explicit coverage_module_tracker(const coverage_config& config);

  void initialize(const w1::runtime::module_registry& modules, coverage_collector& collector);

  template <typename Visitor>
  bool visit_traced_module(
      const w1::runtime::module_registry& modules, uint64_t address, Visitor&& visitor
  ) const;

  size_t traced_module_count() const { return module_map_.size(); }

private:
  bool should_trace_module(const w1::runtime::module_info& module) const;
  uint16_t ensure_module_registered(const w1::runtime::module_info& module) const;

  const coverage_config& config_;
  coverage_collector* collector_ = nullptr;
  mutable std::unordered_map<uint64_t, uint16_t> module_map_;
  redlog::logger log_ = redlog::get_logger("w1cov.module_tracker");
};

template <typename Visitor>
bool coverage_module_tracker::visit_traced_module(
    const w1::runtime::module_registry& modules, uint64_t address, Visitor&& visitor
) const {
  static_assert(
      std::is_invocable_v<Visitor, const w1::runtime::module_info&, uint16_t>,
      "visitor must be callable with (const module_info&, uint16_t)"
  );

  if (address == 0) {
    return false;
  }

  const auto* module = modules.find_containing(address);
  if (!module || !should_trace_module(*module)) {
    return false;
  }

  uint16_t module_id = ensure_module_registered(*module);
  visitor(*module, module_id);
  return true;
}

} // namespace w1cov
