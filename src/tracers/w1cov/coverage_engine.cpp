#include "coverage_engine.hpp"

namespace w1cov {
namespace {
constexpr size_t kDefaultThreadBufferReserve = 4096;
}

coverage_engine::coverage_engine(coverage_config config)
    : config_(std::move(config)), modules_(config_) {}

coverage_engine::thread_writer::thread_writer(coverage_engine* engine, size_t reserve) : engine_(engine) {
  buffer_.reserve(reserve);
}

void coverage_engine::thread_writer::record(QBDI::rword address, uint16_t size) {
  if (!engine_) {
    return;
  }

  uint16_t module_id = 0;
  if (!engine_->resolve_module_id(static_cast<uint64_t>(address), module_id)) {
    return;
  }

  auto& entry = buffer_[static_cast<uint64_t>(address)];
  if (entry.hits == 0) {
    entry.module_id = module_id;
    entry.size = size;
  } else if (entry.size == 0 && size != 0) {
    entry.size = size;
  }
  entry.hits += 1;
}

void coverage_engine::thread_writer::flush() {
  if (!engine_) {
    return;
  }
  engine_->merge_buffer(buffer_);
  buffer_.clear();
}

void coverage_engine::configure(const w1::runtime::module_registry& modules) {
  store_.reset();
  modules_.configure(modules);
  configured_.store(true, std::memory_order_release);
  exported_.store(false, std::memory_order_release);
}

coverage_engine::thread_writer coverage_engine::begin_thread() {
  return thread_writer(this, kDefaultThreadBufferReserve);
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

bool coverage_engine::resolve_module_id(uint64_t address, uint16_t& module_id) const {
  auto id = modules_.find_module_id(address);
  if (!id) {
    return false;
  }
  module_id = *id;
  return true;
}

void coverage_engine::merge_buffer(const coverage_buffer& buffer) { store_.merge(buffer); }

} // namespace w1cov
