#include "memory_collector.hpp"

namespace w1mem {

memory_collector::memory_collector(size_t max_trace_entries, bool collect_trace)
    : max_trace_entries_(max_trace_entries), collect_trace_(collect_trace), instruction_count_(0),
      trace_overflow_(false) {

  stats_ = {};

  if (collect_trace_) {
    trace_.reserve(max_trace_entries_);
  }
}

void memory_collector::record_instruction() {
  instruction_count_++;
  stats_.total_instructions++;
}

void memory_collector::record_memory_access(
    uint64_t instruction_addr, uint64_t memory_addr, uint32_t size, uint8_t access_type
) {

  // update statistics
  if (access_type == 1) { // read
    stats_.total_reads++;
    stats_.total_bytes_read += size;
    if (unique_read_addrs_.insert(memory_addr).second) {
      stats_.unique_read_addresses++;
    }
  } else if (access_type == 2) { // write
    stats_.total_writes++;
    stats_.total_bytes_written += size;
    if (unique_write_addrs_.insert(memory_addr).second) {
      stats_.unique_write_addresses++;
    }
  }

  // record trace entry if enabled and not overflowed
  if (collect_trace_ && !trace_overflow_) {
    if (trace_.size() < max_trace_entries_) {
      memory_access_entry entry;
      entry.instruction_addr = instruction_addr;
      entry.memory_addr = memory_addr;
      entry.size = size;
      entry.access_type = access_type;
      entry.instruction_count = instruction_count_;

      trace_.push_back(entry);
    } else {
      trace_overflow_ = true;
    }
  }
}

w1mem_report memory_collector::build_report() const {
  w1mem_report report;
  report.stats = stats_;

  if (collect_trace_) {
    report.trace = trace_;
  }

  return report;
}

} // namespace w1mem