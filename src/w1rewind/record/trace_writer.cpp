#include "trace_writer.hpp"

#include <filesystem>
#include <limits>
#include <sstream>
#include <system_error>

#include "w1rewind/format/trace_codec.hpp"
#include "w1rewind/format/trace_io.hpp"

#if defined(W1_REWIND_HAVE_ZSTD)
#include <zstd.h>
#endif

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace w1::rewind {

namespace {

constexpr int k_zstd_level = 3;

} // namespace

trace_writer::trace_writer(trace_writer_config config) : config_(std::move(config)) {}

trace_writer::~trace_writer() { close(); }

std::shared_ptr<trace_writer> make_trace_writer(trace_writer_config config) {
  return std::make_shared<trace_writer>(std::move(config));
}

bool trace_writer::open() {
  std::lock_guard<std::mutex> guard(mutex_);
#if !defined(W1_REWIND_HAVE_ZSTD)
  if (config_.compression == trace_compression::zstd) {
    config_.log.err("zstd compression requested but zstd is not available");
    good_ = false;
    return false;
  }
#endif

  if (config_.chunk_size == 0) {
    config_.chunk_size = k_trace_chunk_bytes;
  }
  if (stream_.is_open()) {
    stream_.close();
  }

  path_ = config_.path;
  if (path_.empty()) {
    path_ = make_default_path();
  }

  std::error_code ec;
  std::filesystem::path fs_path(path_);
  if (fs_path.has_parent_path()) {
    std::filesystem::create_directories(fs_path.parent_path(), ec);
    if (ec) {
      config_.log.err(
          "failed to create trace directory", redlog::field("path", fs_path.parent_path().string()),
          redlog::field("error", ec.message())
      );
      good_ = false;
      return false;
    }
  }

  stream_.open(fs_path, std::ios::binary | std::ios::out | std::ios::trunc);
  good_ = stream_.good();
  header_written_ = false;
  chunk_buffer_.clear();
  chunk_encoded_.clear();

  if (!good_) {
    config_.log.err("failed to open trace", redlog::field("path", path_));
    return false;
  }

  config_.log.inf("trace writer ready", redlog::field("path", path_));
  return true;
}

void trace_writer::close() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (stream_.is_open()) {
    if (good_ && header_written_) {
      flush_chunk_locked();
      stream_.flush();
    }
    stream_.close();
  }
  good_ = false;
  header_written_ = false;
  chunk_buffer_.clear();
  chunk_encoded_.clear();
}

bool trace_writer::write_header(const trace_header& header) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!stream_.is_open()) {
    config_.log.err("trace writer not open");
    return false;
  }
  if (header_written_) {
    return true;
  }

  trace_header updated = header;
  updated.compression = config_.compression;
  updated.chunk_size = config_.chunk_size;

  write_bytes(k_trace_magic.data(), k_trace_magic.size());
  write_u16(updated.version);
  write_u16(static_cast<uint16_t>(updated.arch.arch_family));
  write_u16(static_cast<uint16_t>(updated.arch.arch_mode));
  uint8_t byte_order = static_cast<uint8_t>(updated.arch.arch_byte_order);
  write_bytes(&byte_order, sizeof(byte_order));
  uint8_t reserved = 0;
  write_bytes(&reserved, sizeof(reserved));
  write_u32(updated.arch.pointer_bits);
  write_u32(updated.arch.flags);
  write_u64(updated.flags);
  write_u32(static_cast<uint32_t>(updated.compression));
  write_u32(updated.chunk_size);

  if (good_) {
    header_written_ = true;
  } else {
    config_.log.err("failed to write trace header", redlog::field("path", path_));
  }

  return good_;
}

bool trace_writer::write_register_table(const register_table_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_register_table(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::register_table, 0, payload);
}

bool trace_writer::write_target_info(const target_info_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_target_info(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::target_info, 0, payload);
}

bool trace_writer::write_register_spec(const register_spec_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_register_spec(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::register_spec, 0, payload);
}

bool trace_writer::write_module_table(const module_table_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_module_table(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::module_table, 0, payload);
}

bool trace_writer::write_memory_map(const memory_map_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_memory_map(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::memory_map, 0, payload);
}

bool trace_writer::write_thread_start(const thread_start_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_thread_start(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::thread_start, 0, payload);
}

bool trace_writer::write_instruction(const instruction_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_instruction(record, writer);
  return write_record(record_kind::instruction, 0, payload);
}

bool trace_writer::write_block_definition(const block_definition_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_block_definition(record, writer);
  return write_record(record_kind::block_definition, 0, payload);
}

bool trace_writer::write_block_exec(const block_exec_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_block_exec(record, writer);
  return write_record(record_kind::block_exec, 0, payload);
}

bool trace_writer::write_register_deltas(const register_delta_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_register_deltas(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::register_deltas, 0, payload);
}

bool trace_writer::write_register_bytes(const register_bytes_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_register_bytes(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::register_bytes, 0, payload);
}

bool trace_writer::write_memory_access(const memory_access_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_memory_access(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::memory_access, 0, payload);
}

bool trace_writer::write_snapshot(const snapshot_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_snapshot(record, writer, config_.log)) {
    return false;
  }
  return write_record(record_kind::snapshot, 0, payload);
}

bool trace_writer::write_thread_end(const thread_end_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_thread_end(record, writer);
  return write_record(record_kind::thread_end, 0, payload);
}

void trace_writer::flush() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!good_) {
    return;
  }
  flush_chunk_locked();
  stream_.flush();
  if (!stream_.good()) {
    mark_failure();
  }
}

bool trace_writer::write_record(record_kind kind, uint16_t flags, const std::vector<uint8_t>& payload) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!good_) {
    return false;
  }
  if (!header_written_) {
    config_.log.err("trace header not written", redlog::field("path", path_));
    mark_failure();
    return false;
  }

  trace_buffer_writer writer(chunk_buffer_);
  writer.write_u16(static_cast<uint16_t>(kind));
  writer.write_u16(flags);
  writer.write_u32(static_cast<uint32_t>(payload.size()));
  if (!payload.empty()) {
    writer.write_bytes(payload.data(), payload.size());
  }

  if (chunk_buffer_.size() >= config_.chunk_size) {
    return flush_chunk_locked();
  }

  return good_;
}

bool trace_writer::flush_chunk_locked() {
  if (!good_) {
    return false;
  }
  if (chunk_buffer_.empty()) {
    return true;
  }
  if (chunk_buffer_.size() > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("trace chunk too large", redlog::field("size", chunk_buffer_.size()));
    mark_failure();
    return false;
  }

  uint32_t uncompressed_size = static_cast<uint32_t>(chunk_buffer_.size());
  if (config_.compression == trace_compression::none) {
    write_u32(uncompressed_size);
    write_u32(uncompressed_size);
    write_bytes(chunk_buffer_.data(), chunk_buffer_.size());
    chunk_buffer_.clear();
    return good_;
  }

  if (config_.compression != trace_compression::zstd) {
    config_.log.err("unsupported trace compression mode");
    mark_failure();
    return false;
  }

#if defined(W1_REWIND_HAVE_ZSTD)
  size_t bound = ZSTD_compressBound(chunk_buffer_.size());
  if (bound > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("compressed chunk bound too large", redlog::field("size", bound));
    mark_failure();
    return false;
  }
  chunk_encoded_.resize(bound);
  size_t compressed_size =
      ZSTD_compress(chunk_encoded_.data(), bound, chunk_buffer_.data(), chunk_buffer_.size(), k_zstd_level);
  if (ZSTD_isError(compressed_size)) {
    config_.log.err("zstd compression failed", redlog::field("error", ZSTD_getErrorName(compressed_size)));
    mark_failure();
    return false;
  }
  if (compressed_size > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("compressed chunk too large", redlog::field("size", compressed_size));
    mark_failure();
    return false;
  }
  write_u32(static_cast<uint32_t>(compressed_size));
  write_u32(uncompressed_size);
  write_bytes(chunk_encoded_.data(), compressed_size);
  chunk_buffer_.clear();
  return good_;
#else
  config_.log.err("zstd compression requested but zstd is not available");
  mark_failure();
  return false;
#endif
}

void trace_writer::write_u16(uint16_t value) {
  if (!good_) {
    return;
  }
  if (!write_stream_u16(stream_, value)) {
    mark_failure();
  }
}

void trace_writer::write_u32(uint32_t value) {
  if (!good_) {
    return;
  }
  if (!write_stream_u32(stream_, value)) {
    mark_failure();
  }
}

void trace_writer::write_u64(uint64_t value) {
  if (!good_) {
    return;
  }
  if (!write_stream_u64(stream_, value)) {
    mark_failure();
  }
}

void trace_writer::write_bytes(const void* data, size_t size) {
  if (!good_ || size == 0) {
    return;
  }
  if (!write_stream_bytes(stream_, data, size)) {
    mark_failure();
  }
}

void trace_writer::mark_failure() { good_ = false; }

std::string trace_writer::make_default_path() const {
  std::filesystem::path base = std::filesystem::current_path();
#if defined(_WIN32)
  int pid = static_cast<int>(_getpid());
#else
  int pid = static_cast<int>(getpid());
#endif

  std::ostringstream name;
  name << "w1rewind_" << pid << ".trace";
  base /= name.str();
  return base.string();
}

} // namespace w1::rewind
