#include "coverage_engine.hpp"

namespace w1cov {
coverage_engine::coverage_engine(coverage_config config)
    : config_(std::move(config)), modules_(config_) {}

void coverage_engine::configure(const w1::runtime::module_catalog& modules) {
  store_.reset();
  modules_.configure(modules);
  configured_.store(true, std::memory_order_release);
  exported_.store(false, std::memory_order_release);
}

bool coverage_engine::export_coverage() {
  if (exported_.exchange(true, std::memory_order_acq_rel)) {
    return true;
  }

  try {
    auto data = build_drcov_data();
    if (data.basic_blocks.empty()) {
      return false;
    }
    drcov::write(config_.output_file, data);
    return true;
  } catch (...) {
    return false;
  }
}

drcov::coverage_data coverage_engine::build_drcov_data() const {
  coverage_snapshot snapshot = store_.snapshot();
  auto modules = modules_.snapshot_modules();
  return exporter_.to_drcov(snapshot, modules);
}

size_t coverage_engine::coverage_unit_count() const { return store_.unit_count(); }

size_t coverage_engine::module_count() const { return modules_.tracked_module_count(); }

uint64_t coverage_engine::total_hits() const { return store_.total_hits(); }

uint64_t coverage_engine::module_epoch() const { return modules_.registry_version(); }

std::optional<w1::core::module_lookup<uint16_t>> coverage_engine::find_module(uint64_t address) const {
  return modules_.find_module(address);
}

void coverage_engine::merge_buffer(const coverage_buffer& buffer) { store_.merge(buffer); }

} // namespace w1cov
