#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/image_blob_index.hpp"
#include "w1rewind/replay/mapping_types.hpp"

namespace w1::rewind {

struct replay_thread_info {
  uint64_t thread_id = 0;
  std::string name;
  bool started = false;
  bool ended = false;
};

struct register_file_index {
  size_t record_index = 0;
  std::unordered_map<uint32_t, size_t> id_to_index;
  std::unordered_map<std::string, uint32_t> name_to_id;
};

struct replay_context {
  file_header header{};
  std::optional<arch_descriptor_record> arch;
  std::optional<environment_record> environment;

  std::vector<address_space_record> address_spaces;
  std::unordered_map<uint32_t, size_t> address_spaces_by_id;

  std::vector<register_file_record> register_files;
  std::unordered_map<uint32_t, register_file_index> register_files_by_id;

  std::vector<image_record> images;
  std::unordered_map<uint64_t, size_t> images_by_id;
  std::unordered_map<uint64_t, image_metadata_record> image_metadata_by_id;
  std::unordered_map<uint64_t, std::vector<image_blob_record>> image_blobs_by_id;
  std::unordered_map<uint64_t, image_blob_index> image_blob_indexes_by_id;

  std::vector<mapping_record> mappings;
  std::vector<mapping_record> mapping_events;
  std::unordered_map<uint32_t, std::vector<mapping_range>> mapping_ranges_by_space;

  std::unordered_map<uint64_t, block_definition_record> blocks_by_id;
  std::vector<replay_thread_info> threads;

  std::vector<register_spec> default_registers;
  std::vector<std::string> default_register_names;
  std::optional<uint32_t> sp_reg_id;
  std::optional<uint32_t> pc_reg_id;

  struct trace_features {
    bool has_flow_instruction = false;
    bool has_block_exec = false;
    bool has_reg_writes = false;
    bool has_mem_access = false;
    bool has_snapshots = false;
    bool has_mapping_events = false;
    bool has_image_metadata = false;
    bool has_image_blobs = false;
  };

  trace_features features{};

  bool has_block_flow() const { return features.has_block_exec; }
  bool has_instruction_flow() const { return features.has_flow_instruction; }

  const register_file_record* find_register_file(uint32_t regfile_id) const;
  const register_spec* find_register_spec(uint32_t regfile_id, uint32_t reg_id) const;
  std::optional<uint32_t> resolve_register_id(uint32_t regfile_id, std::string_view name) const;
  const address_space_record* find_address_space(uint32_t space_id) const;
  const image_record* find_image(uint64_t image_id) const;
  const image_metadata_record* find_image_metadata(uint64_t image_id) const;
  const mapping_record* find_mapping_for_address(
      uint32_t space_id, uint64_t address, uint64_t size, uint64_t& mapping_offset
  ) const;
  const mapping_range* find_mapping_after(uint32_t space_id, uint64_t address) const;
  const image_blob_index* find_image_blob_index(uint64_t image_id) const;
};

bool load_replay_context(const std::string& trace_path, replay_context& out, std::string& error);
bool validate_replay_context(const replay_context& context, std::string& error);
bool finalize_replay_context(replay_context& context, std::string& error);

} // namespace w1::rewind
