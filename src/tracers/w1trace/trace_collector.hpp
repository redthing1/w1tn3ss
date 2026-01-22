#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "w1formats/jsonl_writer.hpp"
#include "w1runtime/module_catalog.hpp"

#include "trace_config.hpp"

namespace w1trace {

struct insn_event {
  uint64_t step;
  uint64_t address;
};

struct branch_event {
  std::string type;
  uint64_t source;
  uint64_t dest;
};

struct trace_stats {
  uint64_t total_instructions = 0;
  uint64_t total_branches = 0;
  uint64_t total_calls = 0;
  uint64_t total_returns = 0;
  uint64_t total_jumps = 0;
  uint64_t total_conditional = 0;
};

class trace_collector {
public:
  explicit trace_collector(const trace_config& config);
  ~trace_collector();

  void record_instruction(const w1::runtime::module_catalog& modules, uint64_t address);
  void record_branch(const branch_event& event);

  void shutdown();

  size_t get_instruction_count() const { return instruction_count_; }
  const trace_stats& get_stats() const { return stats_; }

private:
  void ensure_metadata_written(const w1::runtime::module_catalog& modules);
  void write_metadata();
  void write_insn_event(const insn_event& event);
  void write_branch_event(const branch_event& event);

  std::string output_file_;
  bool track_control_flow_ = false;
  uint64_t instruction_count_ = 0;
  trace_stats stats_{};

  std::vector<w1::runtime::module_info> modules_{};
  bool modules_cached_ = false;

  std::unique_ptr<w1::io::jsonl_writer> jsonl_writer_;
  bool metadata_written_ = false;
  bool shutdown_called_ = false;

  redlog::logger log_;
};

} // namespace w1trace
