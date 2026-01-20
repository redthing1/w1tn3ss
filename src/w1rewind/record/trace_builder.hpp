#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "trace_builder_types.hpp"

namespace w1::rewind {

class trace_builder {
public:
  explicit trace_builder(trace_builder_config config);

  bool begin_trace(
      const w1::arch::arch_spec& arch, const target_info_record& target, const target_environment_record& environment,
      const std::vector<register_spec>& register_specs
  );
  bool set_module_table(std::vector<module_record> modules);
  bool set_memory_map(std::vector<memory_region_record> regions);

  bool begin_thread(uint64_t thread_id, std::string name = {});
  bool end_thread(uint64_t thread_id);

  bool emit_instruction(uint64_t thread_id, uint64_t address, uint32_t size, uint32_t flags, uint64_t& sequence_out);
  bool emit_block(uint64_t thread_id, uint64_t address, uint32_t size, uint32_t flags, uint64_t& sequence_out);

  bool emit_register_deltas(uint64_t thread_id, uint64_t sequence, std::span<const register_delta> deltas);
  bool emit_register_bytes(
      uint64_t thread_id, uint64_t sequence, std::span<const register_bytes_entry> entries,
      std::span<const uint8_t> data
  );
  bool emit_memory_access(
      uint64_t thread_id, uint64_t sequence, memory_access_kind kind, uint64_t address, uint32_t size, bool value_known,
      bool value_truncated, std::span<const uint8_t> data
  );
  bool emit_snapshot(
      uint64_t thread_id, uint64_t sequence, uint64_t snapshot_id, std::span<const register_delta> registers,
      std::span<const stack_segment> stack_segments, std::string reason
  );

  void flush();
  bool good() const;
  const std::string& error() const { return error_; }

private:
  struct thread_state {
    uint64_t next_sequence = 0;
    bool started = false;
    bool ended = false;
    std::string name;
  };

  struct block_key {
    uint64_t address = 0;
    uint32_t size = 0;
    uint32_t flags = 0;

    bool operator==(const block_key& other) const {
      return address == other.address && size == other.size && flags == other.flags;
    }
  };

  struct block_key_hash {
    size_t operator()(const block_key& key) const noexcept {
      size_t seed = std::hash<uint64_t>{}(key.address);
      seed ^= std::hash<uint32_t>{}(key.size) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      seed ^= std::hash<uint32_t>{}(key.flags) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      return seed;
    }
  };

  bool ensure_trace_started();
  bool ensure_thread_started(thread_state& state, uint64_t thread_id);
  bool write_module_table();
  bool write_memory_map();

  trace_builder_config config_;
  bool started_ = false;
  bool module_table_written_ = false;
  bool memory_map_written_ = false;
  bool module_table_pending_ = false;
  bool memory_map_pending_ = false;

  target_info_record target_info_{};
  target_environment_record target_environment_{};
  std::vector<register_spec> register_specs_{};
  std::vector<module_record> modules_{};
  std::vector<memory_region_record> memory_map_{};

  std::unordered_map<uint64_t, thread_state> threads_{};
  std::unordered_map<block_key, uint64_t, block_key_hash> block_ids_{};
  uint64_t next_block_id_ = 1;

  std::string error_;
};

} // namespace w1::rewind
