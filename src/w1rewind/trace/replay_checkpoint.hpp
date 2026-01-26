#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "record_stream.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct replay_checkpoint_header {
  uint16_t version = k_trace_checkpoint_version;
  uint16_t header_size = 0;
  std::array<uint8_t, 16> trace_uuid{};
  uint32_t flags = 0;
  uint32_t stride = 0;
  uint32_t thread_count = 0;
  uint32_t entry_count = 0;
};

constexpr uint32_t k_checkpoint_flag_has_mappings = 1u << 0;

struct replay_checkpoint_entry {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  trace_record_location location{};
  uint32_t regfile_id = 0;
  std::vector<reg_write_entry> registers;
  std::vector<memory_segment> memory_segments;
  std::vector<mapping_record> mappings;
};

struct replay_checkpoint_thread_index {
  uint64_t thread_id = 0;
  uint32_t entry_start = 0;
  uint32_t entry_count = 0;
};

struct replay_checkpoint_index {
  replay_checkpoint_header header{};
  std::vector<replay_checkpoint_thread_index> threads;
  std::vector<replay_checkpoint_entry> entries;

  const replay_checkpoint_entry* find_checkpoint(uint64_t thread_id, uint64_t sequence) const;
};

struct replay_checkpoint_config {
  std::string trace_path;
  std::string output_path;
  uint32_t stride = 50000;
  bool include_memory = false;
  uint64_t thread_id = 0;
};

std::string default_replay_checkpoint_path(const std::string& trace_path);

bool build_replay_checkpoint(const replay_checkpoint_config& config, replay_checkpoint_index* out, std::string& error);

bool load_replay_checkpoint(const std::string& path, replay_checkpoint_index& out, std::string& error);

} // namespace w1::rewind
