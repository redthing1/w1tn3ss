#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace w1::coverage {

/**
 * Simple standalone coverage tracer
 *
 * Provides hitcount-based coverage collection using QBDI.
 * Much simpler than the previous overcomplicated implementation.
 */
class w1cov_standalone {
public:
  w1cov_standalone();
  ~w1cov_standalone();

  // Core operations
  bool initialize();
  void shutdown();
  bool is_initialized() const { return initialized_; }

  // Coverage collection
  bool trace_function(void* func_ptr, const std::vector<uint64_t>& args = {}, uint64_t* result = nullptr);
  bool trace_address_range(uint64_t start, uint64_t end);

  // Coverage data
  size_t get_unique_blocks() const { return hitcounts_.size(); }
  uint64_t get_total_hits() const;
  uint32_t get_hitcount(uint64_t address) const;
  const std::unordered_map<uint64_t, uint32_t>& get_hitcounts() const { return hitcounts_; }

  // Export
  bool export_drcov(const std::string& filename) const;
  void print_summary() const;

  // Non-copyable
  w1cov_standalone(const w1cov_standalone&) = delete;
  w1cov_standalone& operator=(const w1cov_standalone&) = delete;

  // Public access for callback
  void record_basic_block(uint64_t address, uint16_t size);

private:
  bool initialized_;
  std::unordered_map<uint64_t, uint32_t> hitcounts_;
  std::unordered_map<uint64_t, uint16_t> address_sizes_;
};

} // namespace w1::coverage