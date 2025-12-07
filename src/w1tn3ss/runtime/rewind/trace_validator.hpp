#pragma once

#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

#include <redlog.hpp>

#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>

#include "trace_source.hpp"
#include "trace_types.hpp"

namespace w1::rewind {

enum class validation_mode {
  log_only,
  strict,
};

struct trace_validator_config {
  trace_source_ptr source;
  validation_mode mode = validation_mode::strict;
  uint64_t max_mismatches = 1;
  uint64_t stack_window_bytes = 0x4000;
  std::vector<std::string> ignore_registers;
  std::vector<std::string> ignore_modules;
  redlog::logger log = redlog::get_logger("w1rewind.validator");
};

struct trace_validation_stats {
  uint64_t events_checked = 0;
  uint64_t mismatches = 0;
  bool aborted = false;
};

class trace_validator {
public:
  explicit trace_validator(trace_validator_config config);

  enum class result {
    ok,
    mismatch_logged,
    abort,
  };

  bool initialize();
  void close();

  // verify an emitted event; returns abort when execution should stop
  result verify(const trace_event& live_event);
  // finalize validation and detect missing expected events
  void finalize();

  const trace_validation_stats& stats() const { return stats_; }
  const std::vector<trace_mismatch>& mismatches() const { return mismatches_; }

private:
  struct thread_cursor {
    uint64_t next_sequence = 0;
  };

  struct stack_window {
    std::optional<int64_t> sp_diff;
    std::optional<int64_t> fp_diff;
    std::unordered_map<std::string, int64_t> register_diffs;
    // remember the per-thread stack guard to avoid random canary loads tripping validation
    std::optional<uint64_t> live_canary;
    std::optional<uint64_t> expected_canary;
  };

  // describes the scratch/TLS registers that QBDI itself may reuse across instrumentation boundaries.
  // the list is architecture-specific and derived from the dispatch logic in qbdi/doc/registers.rst.
  struct scratch_register_policy {
    std::unordered_set<std::string> names;
    bool contains(const std::string& reg) const { return names.find(reg) != names.end(); }
  };

  bool fetch_expected(uint64_t thread_id, trace_event& expected);
  bool compare_events(const trace_event& live_event, const trace_event& expected);
  bool compare_instruction_events(const trace_event& live_event, const trace_event& expected);
  bool compare_boundary_events(const trace_event& live_event, const trace_event& expected);

  struct offset_profile {
    std::string reg_name;
    int64_t delta = 0;
    int64_t slack = 0;
    uint64_t boundary_id = 0;
  };

  std::vector<offset_profile>& profiles_for_thread(uint64_t thread_id);
  void reset_profiles(uint64_t thread_id);
  bool check_offset_profiles(
      std::vector<offset_profile>& profiles, const trace_event& live_event, const trace_event& expected,
      const trace_register_delta& actual, const trace_register_delta& target, int64_t diff
  );
  bool compare_registers(
      const trace_event& live_event, const trace_event& expected, std::optional<uint64_t> actual_sp,
      std::optional<uint64_t> expected_sp, std::optional<uint64_t> actual_fp, std::optional<uint64_t> expected_fp
  );
  bool compare_memory(
      const std::vector<trace_memory_delta>& live_accesses, const std::vector<trace_memory_delta>& expected_accesses,
      uint64_t thread_id, uint64_t sequence, const char* kind, std::optional<uint64_t> actual_sp,
      std::optional<uint64_t> expected_sp, std::optional<uint64_t> actual_fp, std::optional<uint64_t> expected_fp
  );
  bool is_stack_canary_write(uint64_t address, size_t size, std::optional<uint64_t> frame_pointer) const;
  bool should_ignore_register(const std::string& name, uint64_t value);
  bool should_ignore_value(uint64_t value);
  void reset_thread_caches(uint64_t thread_id);
  void update_register_cache(
      uint64_t thread_id, const trace_event& event,
      std::unordered_map<uint64_t, std::unordered_map<std::string, uint64_t>>& cache
  );
  std::optional<std::string> module_name_for_address(uint64_t address);
  bool module_matches_ignore(const std::string& module_name) const;
  void record_mismatch(trace_mismatch::kind type, uint64_t thread_id, uint64_t sequence, std::string message);
  const scratch_register_policy& scratch_policy() const;

  trace_validator_config config_;
  trace_validation_stats stats_;
  std::vector<trace_mismatch> mismatches_;
  std::unordered_map<uint64_t, thread_cursor> cursors_;
  std::unordered_map<uint64_t, std::deque<trace_event>> pending_events_;
  std::unordered_map<uint64_t, stack_window> stack_windows_;
  std::unordered_map<uint64_t, std::unordered_map<std::string, uint64_t>> last_actual_registers_;
  std::unordered_map<uint64_t, std::unordered_map<std::string, uint64_t>> last_expected_registers_;
  std::unordered_map<uint64_t, std::vector<offset_profile>> offset_profiles_;
  std::unordered_set<std::string> ignore_registers_;
  std::vector<std::string> ignore_modules_;
  bool module_cache_initialized_ = false;
  w1::util::module_scanner module_scanner_;
  w1::util::module_range_index module_index_;
  scratch_register_policy scratch_policy_;
  bool initialized_ = false;
  bool finalized_ = false;
  std::mutex mutex_;
};

using trace_validator_ptr = std::shared_ptr<trace_validator>;

} // namespace w1::rewind
