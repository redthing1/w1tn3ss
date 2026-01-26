#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "record_stream.hpp"

namespace w1::rewind {

struct trace_index_header {
  uint16_t version = k_trace_index_version;
  uint16_t header_size = 0;
  std::array<uint8_t, 16> trace_uuid{};
  uint32_t flags = 0;
  uint32_t anchor_stride = 0;
  uint32_t thread_count = 0;
  uint32_t reserved = 0;
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
};

struct trace_index_options {
  uint32_t anchor_stride = 50000;
};

struct trace_index {
  trace_index_header header{};
  std::vector<trace_thread_index> threads{};
  std::vector<trace_anchor> anchors{};

  const trace_thread_index* find_thread(uint64_t thread_id) const;
  std::optional<trace_anchor> find_anchor(uint64_t thread_id, uint64_t sequence) const;
};

std::string default_trace_index_path(const std::string& trace_path);

enum class trace_index_status {
  ok,
  missing,
  stale,
  incompatible,
};

bool build_trace_index(
    const std::string& trace_path, const std::string& index_path, const trace_index_options& options, trace_index* out,
    redlog::logger log
);

bool load_trace_index(const std::string& index_path, trace_index& out, redlog::logger log);

trace_index_status evaluate_trace_index(
    const std::filesystem::path& trace_path, const std::filesystem::path& index_path, const trace_index& index,
    std::string& error
);

bool ensure_trace_index(
    const std::filesystem::path& trace_path, const std::filesystem::path& index_path,
    const trace_index_options& options, trace_index& out, std::string& error, bool allow_build = true
);

} // namespace w1::rewind
