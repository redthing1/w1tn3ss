#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "trace_builder_types.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

class trace_builder {
public:
  explicit trace_builder(trace_builder_config config);

  bool begin_trace(const file_header& header);

  bool write_record(const record_header& header, std::span<const uint8_t> payload);

  bool emit_record_type_dictionary(const record_type_dictionary_record& record);
  bool emit_arch_descriptor(const arch_descriptor_record& record);
  bool emit_arch_descriptor_checked(const arch_descriptor_record& record);
  bool emit_environment(const environment_record& record);
  bool emit_environment_checked(const environment_record& record);
  bool emit_address_space(const address_space_record& record);
  bool emit_register_file(const register_file_record& record);
  bool emit_image(const image_record& record);
  bool emit_image_metadata(const image_metadata_record& record);
  bool emit_image_blob(const image_blob_record& record);
  bool emit_image_blob_range(uint64_t image_id, uint64_t offset, std::span<const uint8_t> bytes);
  bool emit_mapping(const mapping_record& record);
  bool emit_thread_start(const thread_start_record& record);
  bool emit_thread_end(const thread_end_record& record);
  bool emit_flow_instruction(const flow_instruction_record& record);
  bool emit_block_definition(const block_definition_record& record);
  bool emit_block_exec(const block_exec_record& record);
  bool emit_reg_write(const reg_write_record& record);
  bool emit_mem_access(const mem_access_record& record);
  bool emit_snapshot(const snapshot_record& record);
  bool emit_meta(const meta_record& record);

  bool begin_thread(uint64_t thread_id, std::string name = {});
  bool end_thread(uint64_t thread_id);

  bool emit_instruction(
      uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id, uint64_t& sequence_out
  );
  bool emit_block(
      uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id, uint64_t& sequence_out
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
    uint32_t space_id = 0;
    uint16_t mode_id = 0;

    bool operator==(const block_key& other) const {
      return address == other.address && size == other.size && space_id == other.space_id && mode_id == other.mode_id;
    }
  };

  struct block_key_hash {
    size_t operator()(const block_key& key) const noexcept {
      size_t seed = std::hash<uint64_t>{}(key.address);
      seed ^= std::hash<uint32_t>{}(key.size) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      seed ^= std::hash<uint32_t>{}(key.space_id) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      seed ^= std::hash<uint16_t>{}(key.mode_id) + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
      return seed;
    }
  };

  bool ensure_trace_started();
  bool ensure_thread_started(thread_state& state, uint64_t thread_id);

  bool emit_with_codec(uint32_t type_id, const std::vector<uint8_t>& payload);

  trace_builder_config config_;
  bool started_ = false;

  std::unordered_map<uint64_t, thread_state> threads_{};
  std::unordered_map<block_key, uint64_t, block_key_hash> block_ids_{};
  uint64_t next_block_id_ = 1;

  std::string error_;
};

} // namespace w1::rewind
