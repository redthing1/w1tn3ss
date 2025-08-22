#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <optional>
#include <unordered_map>
#include <w1common/ext/jsonstruct.hpp>
#include <w1tn3ss/util/jsonl_writer.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <redlog.hpp>

namespace w1trace {

// instruction execution event
struct insn_event {
  uint64_t step;    // instruction count
  uint64_t address; // instruction pointer

  JS_OBJECT(JS_MEMBER(step), JS_MEMBER(address));
};

// control flow transfer event
struct branch_event {
  std::string type; // "call", "ret", "jmp", "cond"
  uint64_t source;  // branch instruction address
  uint64_t dest;    // target address

  JS_OBJECT(JS_MEMBER(type), JS_MEMBER(source), JS_MEMBER(dest));
};

// statistics tracking
struct trace_stats {
  uint64_t total_instructions;
  uint64_t total_branches;
  uint64_t total_calls;
  uint64_t total_returns;
  uint64_t total_jumps;
  uint64_t total_conditional;

  JS_OBJECT(
      JS_MEMBER(total_instructions), JS_MEMBER(total_branches), JS_MEMBER(total_calls), JS_MEMBER(total_returns),
      JS_MEMBER(total_jumps), JS_MEMBER(total_conditional)
  );
};

class trace_collector {
public:
  explicit trace_collector(const std::string& output_file, bool track_control_flow);
  ~trace_collector();

  // record instruction execution
  void record_instruction(uint64_t address);

  // record branch detection (called when branch mnemonic hit)
  void mark_pending_branch(uint64_t address, const std::string& mnemonic);

  // check and record control flow (called on next instruction)
  void check_control_flow(uint64_t current_address);

  // shutdown and finalize
  void shutdown();

  // statistics
  size_t get_instruction_count() const { return instruction_count_; }
  const trace_stats& get_stats() const { return stats_; }

private:
  // module tracking
  void initialize_module_tracking();
  std::string get_module_name(uint64_t address) const;

  // output handling
  void ensure_metadata_written();
  void write_metadata();
  void write_insn_event(const insn_event& event);
  void write_branch_event(const branch_event& event);

  // branch type classification
  std::string classify_branch_type(const std::string& mnemonic) const;

  std::string output_file_;
  bool track_control_flow_;
  uint64_t instruction_count_;
  uint64_t last_address_;
  trace_stats stats_;

  // branch tracking state
  struct pending_branch {
    uint64_t source_address;
    std::string mnemonic;
    std::string type;
  };
  std::optional<pending_branch> pending_branch_;

  // jsonl output
  std::unique_ptr<w1::util::jsonl_writer> jsonl_writer_;
  bool metadata_written_;

  // module tracking
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  mutable bool modules_initialized_;

  redlog::logger log_;
  bool shutdown_called_;
};

} // namespace w1trace