#pragma once

#include <vector>
#include <unordered_set>
#include <cstdint>
#include <string>
#include <w1common/ext/jsonstruct.hpp>

namespace w1inst {

struct mnemonic_entry {
  uint64_t address;
  std::string mnemonic;
  std::string disassembly;
  uint64_t timestamp;
  uint32_t instruction_count;

  JS_OBJECT(
      JS_MEMBER(address), JS_MEMBER(mnemonic), JS_MEMBER(disassembly), JS_MEMBER(timestamp),
      JS_MEMBER(instruction_count)
  );
};

struct mnemonic_stats {
  uint64_t total_instructions;
  uint64_t matched_instructions;
  std::vector<std::string> target_mnemonics;

  JS_OBJECT(JS_MEMBER(total_instructions), JS_MEMBER(matched_instructions), JS_MEMBER(target_mnemonics));
};

struct w1inst_report {
  mnemonic_stats stats;
  std::vector<mnemonic_entry> trace;

  JS_OBJECT(JS_MEMBER(stats), JS_MEMBER(trace));
};

class mnemonic_collector {
public:
  explicit mnemonic_collector(
      uint64_t max_entries, const std::vector<std::string>& target_mnemonics, bool collect_trace = true
  );

  void record_instruction();
  void record_mnemonic(uint64_t address, const std::string& mnemonic, const std::string& disassembly);

  w1inst_report build_report() const;

  const mnemonic_stats& get_stats() const { return stats_; }
  size_t get_trace_size() const { return trace_.size(); }
  uint32_t get_instruction_count() const { return instruction_count_; }

private:
  mnemonic_stats stats_;
  std::vector<mnemonic_entry> trace_;
  std::unordered_set<std::string> target_mnemonic_set_;

  uint64_t max_entries_;
  uint32_t instruction_count_;
  uint64_t matched_count_;
  bool trace_overflow_;
  bool collect_trace_;

  uint64_t get_timestamp() const;
};

} // namespace w1inst