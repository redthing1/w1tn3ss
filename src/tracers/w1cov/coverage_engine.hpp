#pragma once

#include <atomic>
#include <memory>
#include <unordered_map>

#include <QBDI.h>

#include <w1formats/drcov.hpp>

#include "coverage_config.hpp"
#include "coverage_exporter.hpp"
#include "coverage_store.hpp"
#include "module_index.hpp"

namespace w1cov {

class coverage_engine {
public:
  class thread_writer {
  public:
    thread_writer() = default;

    void record(QBDI::rword address, uint16_t size);
    void flush();
    bool active() const { return engine_ != nullptr; }

  private:
    friend class coverage_engine;

    thread_writer(coverage_engine* engine, size_t reserve);

    coverage_engine* engine_ = nullptr;
    coverage_buffer buffer_{};
  };

  explicit coverage_engine(coverage_config config);

  void configure(const w1::runtime::module_registry& modules);

  thread_writer begin_thread();

  bool export_coverage();
  drcov::coverage_data build_drcov_data() const;

  size_t coverage_unit_count() const;
  size_t module_count() const;
  uint64_t total_hits() const;
  bool is_configured() const { return configured_.load(std::memory_order_acquire); }

  const coverage_config& config() const { return config_; }

private:
  friend class thread_writer;

  bool resolve_module_id(uint64_t address, uint16_t& module_id) const;
  void merge_buffer(const coverage_buffer& buffer);

  coverage_config config_{};
  module_index modules_;
  coverage_store store_{};
  coverage_exporter exporter_{};

  std::atomic<bool> configured_{false};
  std::atomic<bool> exported_{false};
};

} // namespace w1cov
