#pragma once

#include <atomic>
#include <memory>
#include <optional>
#include <string_view>

#include <w1formats/drcov.hpp>

#include "config/coverage_config.hpp"
#include "coverage_exporter.hpp"
#include "coverage_store.hpp"
#include "w1instrument/core/module_registry.hpp"

namespace w1cov {

class coverage_engine {
public:
  explicit coverage_engine(coverage_config config);

  void configure(w1::runtime::module_catalog& modules);
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
  using registry_type = w1::core::module_registry<w1::core::instrumented_module_policy, uint16_t>;

  coverage_config config_{};
  registry_type registry_{};
  coverage_store store_{};
  coverage_exporter exporter_{};

  std::atomic<bool> configured_{false};
  std::atomic<bool> exported_{false};
};

} // namespace w1cov
