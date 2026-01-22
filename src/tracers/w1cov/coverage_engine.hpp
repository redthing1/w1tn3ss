#pragma once

#include <atomic>
#include <memory>
#include <optional>

#include <w1formats/drcov.hpp>

#include "coverage_config.hpp"
#include "coverage_exporter.hpp"
#include "coverage_store.hpp"
#include "module_index.hpp"

namespace w1cov {

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
  coverage_config config_{};
  module_index modules_;
  coverage_store store_{};
  coverage_exporter exporter_{};

  std::atomic<bool> configured_{false};
  std::atomic<bool> exported_{false};
};

} // namespace w1cov
