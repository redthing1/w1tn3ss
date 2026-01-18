#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "trace_reader.hpp"

namespace w1::rewind {

constexpr uint16_t k_trace_index_version = 1;
constexpr std::array<uint8_t, 8> k_trace_index_magic = {'W', '1', 'R', 'N', 'D', 'X', '1', '\0'};

struct trace_index_header {
  uint16_t version = k_trace_index_version;
  uint16_t trace_version = 0;
  uint32_t chunk_size = 0;
  uint64_t trace_flags = 0;
  uint32_t anchor_stride = 0;
};

struct trace_anchor {
  uint64_t sequence = 0;
  uint32_t chunk_index = 0;
  uint32_t record_offset = 0;
};

struct trace_thread_index {
  uint64_t thread_id = 0;
  uint32_t anchor_start = 0;
  uint32_t anchor_count = 0;
  uint32_t snapshot_start = 0;
  uint32_t snapshot_count = 0;
};

struct trace_index_options {
  uint32_t anchor_stride = 50000;
  bool include_snapshots = true;
};

struct trace_index {
  trace_index_header header{};
  std::vector<trace_chunk_info> chunks{};
  std::vector<trace_thread_index> threads{};
  std::vector<trace_anchor> anchors{};
  std::vector<trace_anchor> snapshots{};

  const trace_thread_index* find_thread(uint64_t thread_id) const;
  std::optional<trace_anchor> find_anchor(uint64_t thread_id, uint64_t sequence) const;
  std::optional<trace_anchor> find_snapshot(uint64_t thread_id, uint64_t sequence) const;
};

std::string default_trace_index_path(const std::string& trace_path);

bool build_trace_index(
    const std::string& trace_path,
    const std::string& index_path,
    const trace_index_options& options,
    trace_index* out,
    redlog::logger log
);

bool load_trace_index(const std::string& index_path, trace_index& out, redlog::logger log);

} // namespace w1::rewind
