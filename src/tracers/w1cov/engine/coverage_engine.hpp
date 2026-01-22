#pragma once

#include <atomic>
#include <memory>
#include <optional>
#include <string_view>

#include <w1formats/drcov.hpp>

#include "config/coverage_config.hpp"
#include "coverage_exporter.hpp"
#include "coverage_store.hpp"
#include "w1instrument/core/module_id_map.hpp"

namespace w1cov {

struct coverage_module_policy {
  w1::core::instrumentation_policy instrumentation{};

  bool include(const w1::runtime::module_info& module) const { return instrumentation.should_instrument(module); }

  std::string_view identity(const w1::runtime::module_info& module) const {
    return module.path.empty() ? module.name : module.path;
  }
};

class coverage_engine {
public:
  explicit coverage_engine(coverage_config config);

  void configure(const w1::runtime::module_catalog& modules);
  uint64_t module_epoch() const;
  std::optional<w1::core::module_lookup<uint16_t>> find_module(uint64_t address) const;
  void merge_buffer(const coverage_buffer& buffer);

  bool export_coverage();
  drcov::coverage_data build_drcov_data() const;

  size_t coverage_unit_count() const;
  size_t module_count() const;
  uint64_t total_hits() const;
  bool is_configured() const { return configured_.load(std::memory_order_acquire); }

  const coverage_config& config() const { return config_; }

private:
  using module_map = w1::core::module_id_map<coverage_module_policy, uint16_t>;

  coverage_config config_{};
  module_map modules_;
  coverage_store store_{};
  coverage_exporter exporter_{};

  std::atomic<bool> configured_{false};
  std::atomic<bool> exported_{false};
};

} // namespace w1cov
