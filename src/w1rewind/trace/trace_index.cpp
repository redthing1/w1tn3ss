#include "trace_index.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <unordered_map>

#include "w1rewind/trace/trace_reader.hpp"
#include "w1rewind/format/trace_io.hpp"

namespace w1::rewind {

namespace {

uint32_t normalize_anchor_stride(uint32_t stride) {
  return stride == 0 ? 1u : stride;
}

bool write_index_file(const std::string& path, const trace_index& index, redlog::logger log) {
  std::ofstream out(path, std::ios::binary | std::ios::out | std::ios::trunc);
  if (!out.is_open()) {
    log.err("failed to open index output", redlog::field("path", path));
    return false;
  }

  if (!write_stream_bytes(out, k_trace_index_magic.data(), k_trace_index_magic.size())) {
    return false;
  }
  if (!write_stream_u16(out, index.header.version) || !write_stream_u16(out, index.header.header_size) ||
      !write_stream_bytes(out, index.header.trace_uuid.data(), index.header.trace_uuid.size()) ||
      !write_stream_u32(out, index.header.flags) || !write_stream_u32(out, index.header.anchor_stride) ||
      !write_stream_u32(out, index.header.thread_count) || !write_stream_u32(out, index.header.reserved)) {
    return false;
  }

  for (const auto& thread : index.threads) {
    if (!write_stream_u64(out, thread.thread_id) || !write_stream_u32(out, thread.anchor_start) ||
        !write_stream_u32(out, thread.anchor_count)) {
      return false;
    }
  }

  for (const auto& anchor : index.anchors) {
    if (!write_stream_u64(out, anchor.sequence) || !write_stream_u32(out, anchor.chunk_index) ||
        !write_stream_u32(out, anchor.record_offset)) {
      return false;
    }
  }

  return out.good();
}

} // namespace

const trace_thread_index* trace_index::find_thread(uint64_t thread_id) const {
  for (const auto& thread : threads) {
    if (thread.thread_id == thread_id) {
      return &thread;
    }
  }
  return nullptr;
}

std::optional<trace_anchor> trace_index::find_anchor(uint64_t thread_id, uint64_t sequence) const {
  auto* thread = find_thread(thread_id);
  if (!thread || thread->anchor_count == 0) {
    return std::nullopt;
  }
  uint32_t start = thread->anchor_start;
  uint32_t end = start + thread->anchor_count;
  if (end > anchors.size()) {
    return std::nullopt;
  }

  auto begin = anchors.begin() + static_cast<std::ptrdiff_t>(start);
  auto finish = anchors.begin() + static_cast<std::ptrdiff_t>(end);
  auto it = std::upper_bound(begin, finish, sequence, [](uint64_t value, const trace_anchor& anchor) {
    return value < anchor.sequence;
  });
  if (it == begin) {
    return *begin;
  }
  --it;
  return *it;
}

std::string default_trace_index_path(const std::string& trace_path) { return trace_path + ".w1ridx"; }

bool build_trace_index(
    const std::string& trace_path, const std::string& index_path, const trace_index_options& options, trace_index* out,
    redlog::logger log
) {
  if (!out) {
    return false;
  }

  trace_reader reader(trace_path);
  if (!reader.open()) {
    log.err("failed to open trace", redlog::field("error", reader.error()));
    return false;
  }

  uint32_t stride = normalize_anchor_stride(options.anchor_stride);

  std::unordered_map<uint64_t, std::vector<trace_anchor>> anchors_by_thread;

  trace_record record;
  trace_record_location location{};
  while (reader.read_next(record, &location)) {
    if (std::holds_alternative<flow_instruction_record>(record)) {
      const auto& flow = std::get<flow_instruction_record>(record);
      auto& anchors = anchors_by_thread[flow.thread_id];
      if (anchors.empty() || (flow.sequence % stride) == 0) {
        anchors.push_back({flow.sequence, location.chunk_index, location.record_offset});
      }
    } else if (std::holds_alternative<block_exec_record>(record)) {
      const auto& exec = std::get<block_exec_record>(record);
      auto& anchors = anchors_by_thread[exec.thread_id];
      if (anchors.empty() || (exec.sequence % stride) == 0) {
        anchors.push_back({exec.sequence, location.chunk_index, location.record_offset});
      }
    }
  }

  if (!reader.error().empty()) {
    log.err("trace scan failed", redlog::field("error", reader.error()));
    return false;
  }

  trace_index index;
  index.header.version = k_trace_index_version;
  index.header.header_size = static_cast<uint16_t>(sizeof(trace_index_header));
  index.header.trace_uuid = reader.header().trace_uuid;
  index.header.flags = 0;
  index.header.anchor_stride = stride;
  index.header.thread_count = static_cast<uint32_t>(anchors_by_thread.size());
  index.header.reserved = 0;

  std::vector<uint64_t> thread_ids;
  thread_ids.reserve(anchors_by_thread.size());
  for (const auto& [thread_id, _] : anchors_by_thread) {
    thread_ids.push_back(thread_id);
  }
  std::sort(thread_ids.begin(), thread_ids.end());

  for (uint64_t thread_id : thread_ids) {
    auto& list = anchors_by_thread[thread_id];
    std::sort(list.begin(), list.end(), [](const trace_anchor& a, const trace_anchor& b) {
      return a.sequence < b.sequence;
    });

    trace_thread_index entry{};
    entry.thread_id = thread_id;
    entry.anchor_start = static_cast<uint32_t>(index.anchors.size());
    entry.anchor_count = static_cast<uint32_t>(list.size());
    index.threads.push_back(entry);

    index.anchors.insert(index.anchors.end(), list.begin(), list.end());
  }

  if (!write_index_file(index_path, index, log)) {
    return false;
  }

  *out = std::move(index);
  return true;
}

bool load_trace_index(const std::string& index_path, trace_index& out, redlog::logger log) {
  std::ifstream in(index_path, std::ios::binary | std::ios::in);
  if (!in.is_open()) {
    log.err("failed to open index", redlog::field("path", index_path));
    return false;
  }

  std::array<uint8_t, 8> magic{};
  if (!read_stream_bytes(in, magic.data(), magic.size())) {
    return false;
  }
  if (std::memcmp(magic.data(), k_trace_index_magic.data(), k_trace_index_magic.size()) != 0) {
    log.err("index magic mismatch", redlog::field("path", index_path));
    return false;
  }

  trace_index index;
  if (!read_stream_u16(in, index.header.version) || !read_stream_u16(in, index.header.header_size) ||
      !read_stream_bytes(in, index.header.trace_uuid.data(), index.header.trace_uuid.size()) ||
      !read_stream_u32(in, index.header.flags) || !read_stream_u32(in, index.header.anchor_stride) ||
      !read_stream_u32(in, index.header.thread_count) || !read_stream_u32(in, index.header.reserved)) {
    return false;
  }

  if (index.header.version != k_trace_index_version) {
    log.err("unsupported index version", redlog::field("version", index.header.version));
    return false;
  }

  index.threads.clear();
  index.threads.reserve(index.header.thread_count);
  for (uint32_t i = 0; i < index.header.thread_count; ++i) {
    trace_thread_index entry{};
    if (!read_stream_u64(in, entry.thread_id) || !read_stream_u32(in, entry.anchor_start) ||
        !read_stream_u32(in, entry.anchor_count)) {
      return false;
    }
    index.threads.push_back(entry);
  }

  uint32_t total_anchors = 0;
  for (const auto& thread : index.threads) {
    total_anchors += thread.anchor_count;
  }

  index.anchors.clear();
  index.anchors.reserve(total_anchors);
  for (uint32_t i = 0; i < total_anchors; ++i) {
    trace_anchor anchor{};
    if (!read_stream_u64(in, anchor.sequence) || !read_stream_u32(in, anchor.chunk_index) ||
        !read_stream_u32(in, anchor.record_offset)) {
      return false;
    }
    index.anchors.push_back(anchor);
  }

  out = std::move(index);
  return true;
}

trace_index_status evaluate_trace_index(
    const std::filesystem::path& trace_path, const std::filesystem::path& index_path, const trace_index& index,
    std::string& error
) {
  error.clear();
  if (!std::filesystem::exists(trace_path)) {
    error = "trace file missing";
    return trace_index_status::missing;
  }

  if (!std::filesystem::exists(index_path)) {
    error = "index file missing";
    return trace_index_status::missing;
  }

  trace_reader reader(trace_path.string());
  if (!reader.open()) {
    error = reader.error();
    return trace_index_status::incompatible;
  }

  if (reader.header().trace_uuid != index.header.trace_uuid) {
    error = "trace uuid mismatch";
    return trace_index_status::incompatible;
  }

  auto trace_time = std::filesystem::last_write_time(trace_path);
  auto index_time = std::filesystem::last_write_time(index_path);
  if (trace_time > index_time) {
    error = "index stale";
    return trace_index_status::stale;
  }

  return trace_index_status::ok;
}

bool ensure_trace_index(
    const std::filesystem::path& trace_path, const std::filesystem::path& index_path,
    const trace_index_options& options, trace_index& out, std::string& error, bool allow_build
) {
  error.clear();
  if (!std::filesystem::exists(index_path)) {
    if (!allow_build) {
      error = "trace index missing";
      return false;
    }
    redlog::logger log = redlog::get_logger("w1rewind.trace_index");
    if (!build_trace_index(trace_path.string(), index_path.string(), options, &out, log)) {
      error = "failed to build trace index";
      return false;
    }
    return true;
  }

  redlog::logger log = redlog::get_logger("w1rewind.trace_index");
  if (!load_trace_index(index_path.string(), out, log)) {
    error = "failed to load trace index";
    return false;
  }

  trace_index_status status = evaluate_trace_index(trace_path, index_path, out, error);
  if (status == trace_index_status::ok) {
    const uint32_t expected_stride = normalize_anchor_stride(options.anchor_stride);
    if (out.header.anchor_stride == expected_stride) {
      return true;
    }
    error = "index anchor stride mismatch";
    status = trace_index_status::stale;
  }
  if (!allow_build) {
    return false;
  }
  if (!build_trace_index(trace_path.string(), index_path.string(), options, &out, log)) {
    error = "failed to rebuild trace index";
    return false;
  }
  return true;
}

} // namespace w1::rewind
