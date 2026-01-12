#include "coverage_runtime.hpp"

#include <stdexcept>

namespace w1cov {

namespace {
constexpr size_t kDefaultThreadBufferReserve = 4096;
}

void coverage_thread_buffer::record(QBDI::rword address, uint16_t size, uint16_t module_id) {
  auto& entry = entries_[address];
  if (entry.hits == 0) {
    entry.module_id = module_id;
    entry.size = size;
  } else {
    if (entry.size == 0 && size != 0) {
      entry.size = size;
    }
  }
  entry.hits += 1;
}

void coverage_thread_buffer::clear() { entries_.clear(); }

coverage_runtime& coverage_runtime::instance() {
  static coverage_runtime runtime;
  return runtime;
}

coverage_runtime::coverage_runtime() : module_tracker_(std::make_unique<coverage_module_tracker>(config_)) {}

void coverage_runtime::configure(const coverage_config& config) {
  std::lock_guard<std::mutex> lock(mutex_);

  config_ = config;
  collector_ = coverage_collector{};
  module_tracker_ = std::make_unique<coverage_module_tracker>(config_);
  module_tracker_->initialize(collector_);

  configured_ = true;
}

void coverage_runtime::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  collector_ = coverage_collector{};
  module_tracker_.reset();
  configured_ = false;
}

coverage_thread_buffer coverage_runtime::create_thread_buffer() const {
  return coverage_thread_buffer(kDefaultThreadBufferReserve);
}

void coverage_runtime::record_block(coverage_thread_buffer& buffer, QBDI::rword address, uint16_t size) {
  if (!configured_ || !module_tracker_) {
    return;
  }

  if (address == 0 || size == 0) {
    return;
  }

  bool recorded = module_tracker_->visit_traced_module(address, [&](const w1::util::module_info&, uint16_t module_id) {
    buffer.record(address, size, module_id);
  });

  if (recorded) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  module_tracker_->try_rescan_and_visit(address, [&](const w1::util::module_info&, uint16_t module_id) {
    buffer.record(address, size, module_id);
  });
}

void coverage_runtime::merge_buffer(const coverage_thread_buffer& buffer) {
  if (!configured_) {
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& [address, entry] : buffer.entries()) {
    collector_.record_coverage_unit(address, entry.size, entry.module_id, entry.hits);
  }
}

drcov::coverage_data coverage_runtime::build_drcov_data() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return collector_.build_drcov_data();
}

size_t coverage_runtime::coverage_unit_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return collector_.get_coverage_unit_count();
}

size_t coverage_runtime::module_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return collector_.get_module_count();
}

uint64_t coverage_runtime::total_hits() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return collector_.get_total_hits();
}

coverage_module_tracker& coverage_runtime::module_tracker() {
  if (!module_tracker_) {
    throw std::runtime_error("coverage runtime not configured");
  }
  return *module_tracker_;
}

const coverage_module_tracker& coverage_runtime::module_tracker() const {
  if (!module_tracker_) {
    throw std::runtime_error("coverage runtime not configured");
  }
  return *module_tracker_;
}

coverage_collector& coverage_runtime::collector() { return collector_; }

const coverage_collector& coverage_runtime::collector() const { return collector_; }

} // namespace w1cov
