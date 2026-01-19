#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "trace_reader.hpp"

namespace w1::rewind {

constexpr uint16_t k_replay_checkpoint_version = 3;
constexpr std::array<uint8_t, 8> k_replay_checkpoint_magic = {'W', '1', 'R', 'C', 'H', 'K', '3', '\0'};

struct replay_checkpoint_header {
  uint16_t version = k_replay_checkpoint_version;
  uint16_t trace_version = 0;
  w1::arch::arch_spec arch{};
  uint64_t trace_flags = 0;
  uint32_t register_count = 0;
  uint32_t stride = 0;
};

struct replay_checkpoint_entry {
  uint64_t thread_id = 0;
  uint64_t sequence = 0;
  trace_record_location location{};
  std::vector<register_delta> registers;
  std::vector<register_bytes_entry> register_bytes_entries;
  std::vector<uint8_t> register_bytes;
  std::vector<std::pair<uint64_t, uint8_t>> memory;
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

bool build_replay_checkpoint(
    const replay_checkpoint_config& config,
    replay_checkpoint_index* out,
    std::string& error
);

bool load_replay_checkpoint(const std::string& path, replay_checkpoint_index& out, std::string& error);

} // namespace w1::rewind
