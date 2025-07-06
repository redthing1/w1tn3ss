#include "instruction_collector.hpp"
#include <chrono>
#include <sstream>

namespace w1inst {

mnemonic_collector::mnemonic_collector(uint64_t max_entries, const std::vector<std::string>& target_mnemonics, bool collect_trace)
    : max_entries_(max_entries), instruction_count_(0), matched_count_(0), trace_overflow_(false), collect_trace_(collect_trace) {

  stats_ = {};
  stats_.target_mnemonics = target_mnemonics;

  // convert vector to set for faster lookup
  for (const auto& mnemonic : target_mnemonics) {
    target_mnemonic_set_.insert(mnemonic);
  }

  if (collect_trace_) {
    trace_.reserve(max_entries_);
  }
}

void mnemonic_collector::record_instruction() {
  instruction_count_++;
  stats_.total_instructions++;
}

void mnemonic_collector::record_mnemonic(
    uint64_t address, const std::string& mnemonic, const std::string& disassembly
) {
  // check if this mnemonic matches our targets
  bool matches = false;

  // special case: '*' means match all instructions
  if (target_mnemonic_set_.count("*")) {
    matches = true;
  } else {
    // exact string matching
    matches = (target_mnemonic_set_.find(mnemonic) != target_mnemonic_set_.end());
  }

  if (!matches) {
    return; // not a target mnemonic
  }

  matched_count_++;
  stats_.matched_instructions++;

  // record trace entry if enabled and not overflowed
  if (collect_trace_ && !trace_overflow_) {
    if (trace_.size() < max_entries_) {
      mnemonic_entry entry;
      entry.address = address;
      entry.mnemonic = mnemonic;
      entry.disassembly = disassembly;
      entry.timestamp = get_timestamp();
      entry.instruction_count = instruction_count_;

      trace_.push_back(entry);
    } else {
      trace_overflow_ = true;
    }
  }
}

w1inst_report mnemonic_collector::build_report() const {
  w1inst_report report;
  report.stats = stats_;
  if (collect_trace_) {
    report.trace = trace_;
  }
  return report;
}

uint64_t mnemonic_collector::get_timestamp() const {
  auto now = std::chrono::high_resolution_clock::now();
  auto duration = now.time_since_epoch();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

} // namespace w1inst