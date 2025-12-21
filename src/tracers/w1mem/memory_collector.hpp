#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <redlog.hpp>

#include "w1tn3ss/io/jsonl_writer.hpp"
#include "w1tn3ss/runtime/module_registry.hpp"

#include "memory_config.hpp"

namespace w1mem {

struct memory_access_entry {
  uint64_t instruction_addr = 0;
  uint64_t memory_addr = 0;
  uint32_t size = 0;
  uint8_t access_type = 0;
  uint32_t instruction_count = 0;
  std::string instruction_module;
  std::string memory_module;
  uint64_t value = 0;
  bool value_valid = false;
};

struct memory_stats {
  uint64_t total_reads = 0;
  uint64_t total_writes = 0;
  uint64_t total_bytes_read = 0;
  uint64_t total_bytes_written = 0;
  uint64_t unique_read_addresses = 0;
  uint64_t unique_write_addresses = 0;
  uint64_t total_instructions = 0;
};

class memory_collector {
public:
  explicit memory_collector(const memory_config& config);

  void record_instruction();
  void record_memory_access(
      const w1::runtime::module_registry& modules, uint64_t instruction_addr, uint64_t memory_addr, uint32_t size,
      uint8_t access_type, uint64_t value, bool value_valid
  );

  const memory_stats& get_stats() const { return stats_; }
  uint32_t get_instruction_count() const { return instruction_count_; }

private:
  void ensure_metadata_written(const w1::runtime::module_registry& modules);
  void write_metadata();
  void write_event(const memory_access_entry& entry);
  std::string get_module_name(const w1::runtime::module_registry& modules, uint64_t address) const;

  memory_config config_{};
  memory_stats stats_{};
  std::unordered_set<uint64_t> unique_read_addrs_{};
  std::unordered_set<uint64_t> unique_write_addrs_{};

  uint32_t instruction_count_ = 0;

  std::unique_ptr<w1::io::jsonl_writer> jsonl_writer_;
  bool metadata_written_ = false;

  std::vector<w1::runtime::module_info> modules_{};
  bool modules_cached_ = false;

  redlog::logger log_ = redlog::get_logger("w1mem.collector");
};

} // namespace w1mem
