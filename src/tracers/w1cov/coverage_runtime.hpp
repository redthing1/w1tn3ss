#pragma once

#include <mutex>
#include <unordered_map>

#include <QBDI.h>

#include <w1tn3ss/formats/drcov.hpp>

#include "coverage_collector.hpp"
#include "coverage_config.hpp"
#include "coverage_module_tracker.hpp"

namespace w1cov {

struct coverage_thread_buffer_entry {
  uint16_t module_id = 0;
  uint16_t size = 0;
  uint32_t hits = 0;
};

class coverage_thread_buffer {
public:
  coverage_thread_buffer() = default;
  explicit coverage_thread_buffer(size_t reserve) { entries_.reserve(reserve); }

  void record(QBDI::rword address, uint16_t size, uint16_t module_id);
  void clear();

  const std::unordered_map<QBDI::rword, coverage_thread_buffer_entry>& entries() const { return entries_; }
  size_t size() const { return entries_.size(); }

private:
  std::unordered_map<QBDI::rword, coverage_thread_buffer_entry> entries_;
};

class coverage_runtime {
public:
  static coverage_runtime& instance();

  void configure(const coverage_config& config);
  void reset();

  coverage_thread_buffer create_thread_buffer() const;
  void record_block(coverage_thread_buffer& buffer, QBDI::rword address, uint16_t size);

  void merge_buffer(const coverage_thread_buffer& buffer);

  drcov::coverage_data build_drcov_data() const;
  size_t coverage_unit_count() const;
  size_t module_count() const;
  uint64_t total_hits() const;
  bool is_configured() const { return configured_; }

  const coverage_config& config() const { return config_; }

  coverage_module_tracker& module_tracker();
  const coverage_module_tracker& module_tracker() const;
  coverage_collector& collector();
  const coverage_collector& collector() const;

private:
  coverage_runtime();

  coverage_config config_{};
  coverage_collector collector_;
  std::unique_ptr<coverage_module_tracker> module_tracker_;

  mutable std::mutex mutex_;
  bool configured_ = false;
};

} // namespace w1cov
