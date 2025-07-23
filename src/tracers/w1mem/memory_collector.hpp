#pragma once

#include <unordered_set>
#include <cstdint>
#include <string>
#include <memory>
#include <w1common/ext/jsonstruct.hpp>
#include <w1tn3ss/util/jsonl_writer.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <redlog.hpp>

namespace w1mem {

struct memory_access_entry {
  uint64_t instruction_addr;
  uint64_t memory_addr;
  uint32_t size;
  uint8_t access_type; // 1=read, 2=write
  uint32_t instruction_count;
  std::string instruction_module;
  std::string memory_module;
  uint64_t value;   // memory value read/written (up to 8 bytes)
  bool value_valid; // false if MEMORY_UNKNOWN_VALUE flag is set

  JS_OBJECT(
      JS_MEMBER(instruction_addr), JS_MEMBER(memory_addr), JS_MEMBER(size), JS_MEMBER(access_type),
      JS_MEMBER(instruction_count), JS_MEMBER(instruction_module), JS_MEMBER(memory_module), JS_MEMBER(value),
      JS_MEMBER(value_valid)
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

class memory_collector {
public:
  explicit memory_collector(const std::string& output_file);

  void record_instruction();
  void record_memory_access(
      uint64_t instruction_addr, uint64_t memory_addr, uint32_t size, uint8_t access_type, uint64_t value,
      bool value_valid
  );

  const memory_stats& get_stats() const { return stats_; }
  uint32_t get_instruction_count() const { return instruction_count_; }

private:
  memory_stats stats_;
  std::unordered_set<uint64_t> unique_read_addrs_;
  std::unordered_set<uint64_t> unique_write_addrs_;

  uint32_t instruction_count_;

  // jsonl output
  std::unique_ptr<w1::util::jsonl_writer> jsonl_writer_;
  bool metadata_written_;

  // module tracking
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  bool modules_initialized_;

  redlog::logger log_ = redlog::get_logger("w1.mem.collector");

  void ensure_metadata_written();
  void write_metadata();
  void write_event(const memory_access_entry& entry);
  void initialize_module_tracking();
  std::string get_module_name(uint64_t address) const;
};

} // namespace w1mem