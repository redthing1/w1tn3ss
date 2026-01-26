#include "trace_file_writer.hpp"

#include <filesystem>
#include <limits>
#include <sstream>
#include <system_error>

#include "w1rewind/format/trace_io.hpp"

#if defined(WITNESS_REWIND_HAVE_ZSTD)
#include <zstd.h>
#endif

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace w1::rewind {

namespace {
#if defined(WITNESS_REWIND_HAVE_ZSTD)
constexpr int k_zstd_level = 3;
#endif
} // namespace

trace_file_writer::trace_file_writer(trace_file_writer_config config) : config_(std::move(config)) {}

trace_file_writer::~trace_file_writer() { close(); }

std::shared_ptr<trace_file_writer> make_trace_file_writer(trace_file_writer_config config) {
  return std::make_shared<trace_file_writer>(std::move(config));
}

bool trace_file_writer::open() {
  std::lock_guard<std::mutex> guard(mutex_);
#if !defined(WITNESS_REWIND_HAVE_ZSTD)
  if (config_.codec == compression::zstd) {
    config_.log.err("zstd compression requested but zstd is not available");
    good_ = false;
    return false;
  }
#endif

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
  chunk_size_ = 0;
  chunk_buffer_.clear();
  chunk_encoded_.clear();
  chunk_directory_.clear();

  if (!good_) {
    config_.log.err("failed to open trace", redlog::field("path", path_));
    return false;
  }

  config_.log.inf("trace writer ready", redlog::field("path", path_));
  return true;
}

void trace_file_writer::close() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (stream_.is_open()) {
    if (good_ && header_written_) {
      flush_chunk_locked();
      // write chunk directory and footer
      uint64_t directory_offset = static_cast<uint64_t>(stream_.tellp());
      for (const auto& entry : chunk_directory_) {
        write_u64(entry.chunk_file_offset);
        write_u32(entry.compressed_size);
        write_u32(entry.uncompressed_size);
        write_u16(static_cast<uint16_t>(entry.codec));
        write_u16(entry.flags);
      }
      uint64_t directory_size = static_cast<uint64_t>(chunk_directory_.size() * k_chunk_dir_entry_size);

      write_bytes(k_trace_footer_magic.data(), k_trace_footer_magic.size());
      write_u16(k_trace_version);
      uint16_t footer_size = static_cast<uint16_t>(
          sizeof(k_trace_footer_magic) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint64_t) +
          sizeof(uint64_t) + sizeof(uint32_t)
      );
      write_u16(footer_size);
      write_u32(static_cast<uint32_t>(chunk_directory_.size()));
      write_u64(directory_offset);
      write_u64(directory_size);
      write_u32(0);

      stream_.flush();
    }
    stream_.close();
  }
  good_ = false;
  header_written_ = false;
  chunk_size_ = 0;
  chunk_buffer_.clear();
  chunk_encoded_.clear();
  chunk_directory_.clear();
}

bool trace_file_writer::write_header(const file_header& header) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!stream_.is_open()) {
    config_.log.err("trace writer not open");
    return false;
  }
  if (header_written_) {
    return true;
  }

  file_header updated = header;
  updated.header_size = static_cast<uint16_t>(sizeof(file_header));
  if (config_.chunk_size == 0) {
    config_.chunk_size = header.default_chunk_size == 0 ? (8u * 1024u * 1024u) : header.default_chunk_size;
  }
  updated.default_chunk_size = config_.chunk_size;

  write_bytes(k_trace_magic.data(), k_trace_magic.size());
  write_u16(updated.version);
  write_u16(updated.header_size);
  write_u32(updated.flags);
  write_bytes(updated.trace_uuid.data(), updated.trace_uuid.size());
  write_u32(updated.default_chunk_size);
  write_u32(updated.reserved);

  if (good_) {
    header_written_ = true;
    chunk_size_ = updated.default_chunk_size;
  } else {
    config_.log.err("failed to write trace header", redlog::field("path", path_));
  }

  return good_;
}

bool trace_file_writer::write_record(const record_header& header, std::span<const uint8_t> payload) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!good_) {
    return false;
  }
  if (!header_written_) {
    config_.log.err("trace header not written", redlog::field("path", path_));
    mark_failure();
    return false;
  }
  if (chunk_size_ == 0) {
    config_.log.err("trace chunk size invalid");
    mark_failure();
    return false;
  }
  if (header.payload_size != payload.size()) {
    config_.log.err("record payload size mismatch", redlog::field("size", payload.size()));
    mark_failure();
    return false;
  }

  uint64_t record_size = sizeof(record_header) + payload.size();
  if (record_size > chunk_size_) {
    config_.log.err("record larger than chunk size", redlog::field("size", record_size));
    mark_failure();
    return false;
  }

  if (chunk_buffer_.size() + record_size > chunk_size_) {
    if (!flush_chunk_locked()) {
      return false;
    }
  }

  trace_buffer_writer writer(chunk_buffer_);
  writer.write_u32(header.type_id);
  writer.write_u16(header.version);
  writer.write_u16(header.flags);
  writer.write_u32(header.payload_size);
  if (!payload.empty()) {
    writer.write_bytes(payload.data(), payload.size());
  }

  return good_;
}

void trace_file_writer::flush() {
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

bool trace_file_writer::flush_chunk_locked() {
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
  uint64_t chunk_offset = static_cast<uint64_t>(stream_.tellp());

  if (config_.codec == compression::none) {
    write_u32(uncompressed_size);
    write_u32(uncompressed_size);
    write_u16(static_cast<uint16_t>(config_.codec));
    write_u16(0);
    write_u32(0);
    write_bytes(chunk_buffer_.data(), chunk_buffer_.size());

    chunk_dir_entry entry{};
    entry.chunk_file_offset = chunk_offset;
    entry.compressed_size = uncompressed_size;
    entry.uncompressed_size = uncompressed_size;
    entry.codec = config_.codec;
    entry.flags = 0;
    chunk_directory_.push_back(entry);

    chunk_buffer_.clear();
    return good_;
  }

  if (config_.codec != compression::zstd) {
    config_.log.err("unsupported trace compression mode");
    mark_failure();
    return false;
  }

#if defined(WITNESS_REWIND_HAVE_ZSTD)
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
  write_u16(static_cast<uint16_t>(config_.codec));
  write_u16(0);
  write_u32(0);
  write_bytes(chunk_encoded_.data(), compressed_size);

  chunk_dir_entry entry{};
  entry.chunk_file_offset = chunk_offset;
  entry.compressed_size = static_cast<uint32_t>(compressed_size);
  entry.uncompressed_size = uncompressed_size;
  entry.codec = config_.codec;
  entry.flags = 0;
  chunk_directory_.push_back(entry);

  chunk_buffer_.clear();
  return good_;
#else
  config_.log.err("zstd compression requested but zstd is not available");
  mark_failure();
  return false;
#endif
}

void trace_file_writer::write_u16(uint16_t value) {
  if (!good_) {
    return;
  }
  if (!write_stream_u16(stream_, value)) {
    mark_failure();
  }
}

void trace_file_writer::write_u32(uint32_t value) {
  if (!good_) {
    return;
  }
  if (!write_stream_u32(stream_, value)) {
    mark_failure();
  }
}

void trace_file_writer::write_u64(uint64_t value) {
  if (!good_) {
    return;
  }
  if (!write_stream_u64(stream_, value)) {
    mark_failure();
  }
}

void trace_file_writer::write_bytes(const void* data, size_t size) {
  if (!good_ || size == 0) {
    return;
  }
  if (!write_stream_bytes(stream_, data, size)) {
    mark_failure();
  }
}

void trace_file_writer::mark_failure() { good_ = false; }

std::string trace_file_writer::make_default_path() const {
#if defined(_WIN32)
  std::filesystem::path base = std::filesystem::temp_directory_path();
#else
  std::filesystem::path base = std::filesystem::path("/tmp");
#endif
#if defined(_WIN32)
  int pid = static_cast<int>(_getpid());
#else
  int pid = static_cast<int>(getpid());
#endif

  std::ostringstream name;
  name << "w1rewind_" << pid << ".w1r";
  base /= name.str();
  return base.string();
}

} // namespace w1::rewind
