#pragma once

#include <vector>
#include <unordered_set>
#include <cstdint>
#include <common/ext/jsonstruct.hpp>

namespace w1mem {

struct memory_access_entry {
  uint64_t instruction_addr;
  uint64_t memory_addr;
  uint32_t size;
  uint8_t access_type; // 1=read, 2=write
  uint32_t instruction_count;

  JS_OBJECT(
      JS_MEMBER(instruction_addr), JS_MEMBER(memory_addr), JS_MEMBER(size), JS_MEMBER(access_type),
      JS_MEMBER(instruction_count)
  );
};

struct memory_stats {
  uint64_t total_reads;
  uint64_t total_writes;
  uint64_t total_bytes_read;
  uint64_t total_bytes_written;
  uint64_t unique_read_addresses;
  uint64_t unique_write_addresses;
  uint32_t total_instructions;

  JS_OBJECT(
      JS_MEMBER(total_reads), JS_MEMBER(total_writes), JS_MEMBER(total_bytes_read), JS_MEMBER(total_bytes_written),
      JS_MEMBER(unique_read_addresses), JS_MEMBER(unique_write_addresses), JS_MEMBER(total_instructions)
  );
};

struct w1mem_report {
  memory_stats stats;
  std::vector<memory_access_entry> trace;

  JS_OBJECT(JS_MEMBER(stats), JS_MEMBER(trace));
};

class memory_collector {
public:
  explicit memory_collector(size_t max_trace_entries, bool collect_trace);

  void record_instruction();
  void record_memory_access(uint64_t instruction_addr, uint64_t memory_addr, uint32_t size, uint8_t access_type);

  w1mem_report build_report() const;

  const memory_stats& get_stats() const { return stats_; }
  size_t get_trace_size() const { return trace_.size(); }
  uint32_t get_instruction_count() const { return instruction_count_; }

private:
  memory_stats stats_;
  std::vector<memory_access_entry> trace_;
  std::unordered_set<uint64_t> unique_read_addrs_;
  std::unordered_set<uint64_t> unique_write_addrs_;

  size_t max_trace_entries_;
  bool collect_trace_;
  uint32_t instruction_count_;
  bool trace_overflow_;
};

} // namespace w1mem