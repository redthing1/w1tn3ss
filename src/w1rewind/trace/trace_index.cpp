#include "trace_index.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>

#include "w1rewind/format/trace_io.hpp"
#include "w1rewind/trace/flow_classifier.hpp"
#include "w1rewind/trace/trace_reader.hpp"

namespace w1::rewind {

namespace {

struct thread_build_state {
  uint64_t flow_count = 0;
  std::vector<trace_anchor> anchors;
  std::vector<trace_anchor> snapshots;
};

bool write_index_header(
    std::ostream& out, const trace_index_header& header, uint32_t chunk_count, uint32_t thread_count,
    uint32_t anchor_count, uint32_t snapshot_count
) {
  if (!write_stream_bytes(out, k_trace_index_magic.data(), k_trace_index_magic.size())) {
    return false;
  }
  return write_stream_u16(out, header.version) && write_stream_u16(out, header.trace_version) &&
         write_stream_u32(out, header.chunk_size) && write_stream_u64(out, header.trace_flags) &&
         write_stream_u32(out, header.anchor_stride) && write_stream_u32(out, chunk_count) &&
         write_stream_u32(out, thread_count) && write_stream_u32(out, anchor_count) &&
         write_stream_u32(out, snapshot_count);
}

bool read_index_header(
    std::istream& in, trace_index_header& header, uint32_t& chunk_count, uint32_t& thread_count, uint32_t& anchor_count,
    uint32_t& snapshot_count
) {
  std::array<uint8_t, 8> magic{};
  if (!read_stream_bytes(in, magic.data(), magic.size())) {
    return false;
  }
  if (std::memcmp(magic.data(), k_trace_index_magic.data(), k_trace_index_magic.size()) != 0) {
    return false;
  }
  return read_stream_u16(in, header.version) && read_stream_u16(in, header.trace_version) &&
         read_stream_u32(in, header.chunk_size) && read_stream_u64(in, header.trace_flags) &&
         read_stream_u32(in, header.anchor_stride) && read_stream_u32(in, chunk_count) &&
         read_stream_u32(in, thread_count) && read_stream_u32(in, anchor_count) && read_stream_u32(in, snapshot_count);
}

std::optional<trace_anchor> find_anchor_in_span(
    const std::vector<trace_anchor>& anchors, uint32_t start, uint32_t count, uint64_t sequence
) {
  if (count == 0) {
    return std::nullopt;
  }
  auto begin = anchors.begin() + static_cast<std::vector<trace_anchor>::difference_type>(start);
  auto end = begin + static_cast<std::vector<trace_anchor>::difference_type>(count);
  auto it = std::lower_bound(begin, end, sequence, [](const trace_anchor& anchor, uint64_t value) {
    return anchor.sequence < value;
  });
  if (it == begin) {
    if (it->sequence > sequence) {
      return std::nullopt;
    }
    return *it;
  }
  if (it == end) {
    return *(end - 1);
  }
  if (it->sequence == sequence) {
    return *it;
  }
  return *(it - 1);
}

} // namespace

const trace_thread_index* trace_index::find_thread(uint64_t thread_id) const {
  auto it =
      std::lower_bound(threads.begin(), threads.end(), thread_id, [](const trace_thread_index& entry, uint64_t value) {
        return entry.thread_id < value;
      });
  if (it == threads.end() || it->thread_id != thread_id) {
    return nullptr;
  }
  return &(*it);
}

std::optional<trace_anchor> trace_index::find_anchor(uint64_t thread_id, uint64_t sequence) const {
  const trace_thread_index* entry = find_thread(thread_id);
  if (!entry) {
    return std::nullopt;
  }
  return find_anchor_in_span(anchors, entry->anchor_start, entry->anchor_count, sequence);
}

std::optional<trace_anchor> trace_index::find_snapshot(uint64_t thread_id, uint64_t sequence) const {
  const trace_thread_index* entry = find_thread(thread_id);
  if (!entry) {
    return std::nullopt;
  }
  return find_anchor_in_span(snapshots, entry->snapshot_start, entry->snapshot_count, sequence);
}

std::string default_trace_index_path(const std::string& trace_path) { return trace_path + ".idx"; }

bool build_trace_index(
    const std::string& trace_path, const std::string& index_path, const trace_index_options& options, trace_index* out,
    redlog::logger log
) {
  if (options.anchor_stride == 0) {
    log.err("trace index anchor stride must be non-zero");
    return false;
  }

  trace_reader reader(trace_path);
  if (!reader.open()) {
    log.err(
        "failed to open trace for indexing", redlog::field("path", trace_path), redlog::field("error", reader.error())
    );
    return false;
  }

  trace_index index;
  index.header.trace_version = reader.header().version;
  index.header.trace_flags = reader.header().flags;
  index.header.chunk_size = reader.header().chunk_size;
  index.header.anchor_stride = options.anchor_stride;

  bool use_blocks = (reader.header().flags & trace_flag_blocks) != 0;
  bool use_instructions = (reader.header().flags & trace_flag_instructions) != 0;
  enum class flow_kind { blocks, instructions } flow = flow_kind::blocks;
  if (use_blocks) {
    flow = flow_kind::blocks;
  } else if (use_instructions) {
    flow = flow_kind::instructions;
  } else {
    log.err("trace has no flow records to index", redlog::field("path", trace_path));
    return false;
  }

  std::map<uint64_t, thread_build_state> threads;
  uint32_t last_chunk_index = std::numeric_limits<uint32_t>::max();

  trace_record record;
  trace_record_location location{};
  while (reader.read_next(record, &location)) {
    if (location.chunk_index != last_chunk_index) {
      const auto& chunk_info = reader.last_chunk_info();
      if (!chunk_info) {
        log.err("trace reader missing chunk info", redlog::field("chunk", location.chunk_index));
        return false;
      }
      if (location.chunk_index != index.chunks.size()) {
        log.err("trace chunk index out of order", redlog::field("chunk", location.chunk_index));
        return false;
      }
      index.chunks.push_back(*chunk_info);
      last_chunk_index = location.chunk_index;
    }

    auto flow_record = classify_flow_record(record, flow == flow_kind::blocks);
    if (flow_record) {
      auto& state = threads[flow_record->thread_id];
      if (state.flow_count % options.anchor_stride == 0) {
        state.anchors.push_back(
            trace_anchor{flow_record->sequence, location.chunk_index, location.record_offset}
        );
      }
      state.flow_count += 1;
    } else if (options.include_snapshots && std::holds_alternative<snapshot_record>(record)) {
      const auto& snapshot = std::get<snapshot_record>(record);
      auto& state = threads[snapshot.thread_id];
      state.snapshots.push_back(trace_anchor{snapshot.sequence, location.chunk_index, location.record_offset});
    }
  }

  if (!reader.error().empty()) {
    log.err("trace reader error", redlog::field("error", reader.error()));
    return false;
  }

  for (const auto& [thread_id, state] : threads) {
    trace_thread_index entry{};
    entry.thread_id = thread_id;
    entry.anchor_start = static_cast<uint32_t>(index.anchors.size());
    entry.anchor_count = static_cast<uint32_t>(state.anchors.size());
    index.anchors.insert(index.anchors.end(), state.anchors.begin(), state.anchors.end());
    entry.snapshot_start = static_cast<uint32_t>(index.snapshots.size());
    entry.snapshot_count = static_cast<uint32_t>(state.snapshots.size());
    index.snapshots.insert(index.snapshots.end(), state.snapshots.begin(), state.snapshots.end());
    index.threads.push_back(entry);
  }

  std::ofstream out_stream(index_path, std::ios::binary | std::ios::out | std::ios::trunc);
  if (!out_stream.is_open()) {
    log.err("failed to open trace index output", redlog::field("path", index_path));
    return false;
  }

  if (!write_index_header(
          out_stream, index.header, static_cast<uint32_t>(index.chunks.size()),
          static_cast<uint32_t>(index.threads.size()), static_cast<uint32_t>(index.anchors.size()),
          static_cast<uint32_t>(index.snapshots.size())
      )) {
    log.err("failed to write trace index header", redlog::field("path", index_path));
    return false;
  }

  for (const auto& chunk : index.chunks) {
    if (!write_stream_u64(out_stream, chunk.file_offset) || !write_stream_u32(out_stream, chunk.compressed_size) ||
        !write_stream_u32(out_stream, chunk.uncompressed_size)) {
      log.err("failed to write trace chunk index", redlog::field("path", index_path));
      return false;
    }
  }

  for (const auto& thread : index.threads) {
    if (!write_stream_u64(out_stream, thread.thread_id) || !write_stream_u32(out_stream, thread.anchor_start) ||
        !write_stream_u32(out_stream, thread.anchor_count) || !write_stream_u32(out_stream, thread.snapshot_start) ||
        !write_stream_u32(out_stream, thread.snapshot_count)) {
      log.err("failed to write trace thread index", redlog::field("path", index_path));
      return false;
    }
  }

  for (const auto& anchor : index.anchors) {
    if (!write_stream_u64(out_stream, anchor.sequence) || !write_stream_u32(out_stream, anchor.chunk_index) ||
        !write_stream_u32(out_stream, anchor.record_offset)) {
      log.err("failed to write trace anchor index", redlog::field("path", index_path));
      return false;
    }
  }

  for (const auto& anchor : index.snapshots) {
    if (!write_stream_u64(out_stream, anchor.sequence) || !write_stream_u32(out_stream, anchor.chunk_index) ||
        !write_stream_u32(out_stream, anchor.record_offset)) {
      log.err("failed to write trace snapshot index", redlog::field("path", index_path));
      return false;
    }
  }

  if (!out_stream.good()) {
    log.err("failed to flush trace index", redlog::field("path", index_path));
    return false;
  }

  if (out) {
    *out = std::move(index);
  }
  return true;
}

bool load_trace_index(const std::string& index_path, trace_index& out, redlog::logger log) {
  std::ifstream in(index_path, std::ios::binary | std::ios::in);
  if (!in.is_open()) {
    log.err("failed to open trace index", redlog::field("path", index_path));
    return false;
  }

  trace_index index;
  uint32_t chunk_count = 0;
  uint32_t thread_count = 0;
  uint32_t anchor_count = 0;
  uint32_t snapshot_count = 0;

  if (!read_index_header(in, index.header, chunk_count, thread_count, anchor_count, snapshot_count)) {
    log.err("invalid trace index header", redlog::field("path", index_path));
    return false;
  }

  if (index.header.version != k_trace_index_version) {
    log.err("unsupported trace index version", redlog::field("version", index.header.version));
    return false;
  }

  index.chunks.resize(chunk_count);
  for (auto& chunk : index.chunks) {
    if (!read_stream_u64(in, chunk.file_offset) || !read_stream_u32(in, chunk.compressed_size) ||
        !read_stream_u32(in, chunk.uncompressed_size)) {
      log.err("failed to read trace chunk index", redlog::field("path", index_path));
      return false;
    }
  }

  index.threads.resize(thread_count);
  for (auto& thread : index.threads) {
    if (!read_stream_u64(in, thread.thread_id) || !read_stream_u32(in, thread.anchor_start) ||
        !read_stream_u32(in, thread.anchor_count) || !read_stream_u32(in, thread.snapshot_start) ||
        !read_stream_u32(in, thread.snapshot_count)) {
      log.err("failed to read trace thread index", redlog::field("path", index_path));
      return false;
    }
  }

  index.anchors.resize(anchor_count);
  for (auto& anchor : index.anchors) {
    if (!read_stream_u64(in, anchor.sequence) || !read_stream_u32(in, anchor.chunk_index) ||
        !read_stream_u32(in, anchor.record_offset)) {
      log.err("failed to read trace anchor index", redlog::field("path", index_path));
      return false;
    }
  }

  index.snapshots.resize(snapshot_count);
  for (auto& anchor : index.snapshots) {
    if (!read_stream_u64(in, anchor.sequence) || !read_stream_u32(in, anchor.chunk_index) ||
        !read_stream_u32(in, anchor.record_offset)) {
      log.err("failed to read trace snapshot index", redlog::field("path", index_path));
      return false;
    }
  }

  for (const auto& thread : index.threads) {
    if (thread.anchor_start + thread.anchor_count > index.anchors.size()) {
      log.err("trace index anchor range out of bounds", redlog::field("thread_id", thread.thread_id));
      return false;
    }
    if (thread.snapshot_start + thread.snapshot_count > index.snapshots.size()) {
      log.err("trace index snapshot range out of bounds", redlog::field("thread_id", thread.thread_id));
      return false;
    }
  }

  out = std::move(index);
  return true;
}

trace_index_status evaluate_trace_index(
    const std::filesystem::path& trace_path, const trace_index& index, std::string& error
) {
  error.clear();

  if (!std::filesystem::exists(trace_path)) {
    error = "trace file missing";
    return trace_index_status::missing;
  }

  trace_reader reader(trace_path.string());
  if (!reader.open()) {
    error = reader.error().empty() ? "failed to open trace" : std::string(reader.error());
    return trace_index_status::incompatible;
  }

  if (index.header.version != k_trace_index_version) {
    error = "trace index version mismatch";
    return trace_index_status::incompatible;
  }
  if (index.header.trace_version != reader.header().version) {
    error = "trace index trace version mismatch";
    return trace_index_status::incompatible;
  }
  if (index.header.trace_flags != reader.header().flags) {
    error = "trace index flags mismatch";
    return trace_index_status::incompatible;
  }
  if (index.header.chunk_size != reader.header().chunk_size) {
    error = "trace index chunk size mismatch";
    return trace_index_status::incompatible;
  }

  if (!index.chunks.empty()) {
    std::error_code ec;
    uint64_t file_size = static_cast<uint64_t>(std::filesystem::file_size(trace_path, ec));
    if (!ec) {
      const auto& last = index.chunks.back();
      uint64_t last_end = last.file_offset + 8u + last.compressed_size;
      if (file_size > last_end) {
        error = "trace index stale";
        return trace_index_status::stale;
      }
      if (file_size < last_end) {
        error = "trace index exceeds trace size";
        return trace_index_status::incompatible;
      }
    }
  }

  return trace_index_status::ok;
}

bool ensure_trace_index(
    const std::filesystem::path& trace_path, const std::filesystem::path& index_path,
    const trace_index_options& options, trace_index& out, std::string& error, bool allow_build
) {
  error.clear();

  if (trace_path.empty()) {
    error = "trace path required";
    return false;
  }
  if (!std::filesystem::exists(trace_path)) {
    error = "trace file missing";
    return false;
  }

  std::filesystem::path resolved_index = index_path;
  if (resolved_index.empty()) {
    resolved_index = default_trace_index_path(trace_path.string());
  }

  auto log = redlog::get_logger("w1rewind.trace_index");
  trace_index loaded;
  bool index_available = std::filesystem::exists(resolved_index);

  if (index_available) {
    if (!load_trace_index(resolved_index.string(), loaded, log)) {
      if (!allow_build) {
        error = "failed to load trace index";
        return false;
      }
      index_available = false;
    }
  }

  if (index_available) {
    std::string status_error;
    trace_index_status status = evaluate_trace_index(trace_path, loaded, status_error);

    if (status == trace_index_status::ok) {
      std::error_code trace_ec;
      std::error_code index_ec;
      auto trace_time = std::filesystem::last_write_time(trace_path, trace_ec);
      auto index_time = std::filesystem::last_write_time(resolved_index, index_ec);
      if (!trace_ec && !index_ec && trace_time > index_time) {
        status = trace_index_status::stale;
        status_error = "trace index stale";
      }
    }

    if (status == trace_index_status::ok) {
      out = std::move(loaded);
      return true;
    }
    if (!allow_build) {
      error = status_error.empty() ? "trace index invalid" : status_error;
      return false;
    }
  } else if (!allow_build) {
    error = "trace index missing";
    return false;
  }

  if (!build_trace_index(trace_path.string(), resolved_index.string(), options, &out, log)) {
    error = "failed to build trace index";
    return false;
  }

  return true;
}

} // namespace w1::rewind
