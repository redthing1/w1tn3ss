#include "trace_reader.hpp"

#include <array>
#include <cstring>
#include <limits>

#if defined(W1_REWIND_HAVE_ZSTD)
#include <zstd.h>
#endif

#include "w1rewind/format/trace_codec.hpp"
#include "w1rewind/format/trace_io.hpp"

namespace w1::rewind {

trace_reader::trace_reader(std::string path) : path_(std::move(path)) {}

bool trace_reader::open() {
  close();
  stream_.open(path_, std::ios::binary | std::ios::in);
  if (!stream_.is_open()) {
    error_ = "failed to open trace file";
    return false;
  }

  return read_header();
}

void trace_reader::close() {
  if (stream_.is_open()) {
    stream_.close();
  }
  header_read_ = false;
  chunk_buffer_.clear();
  chunk_offset_ = 0;
  next_chunk_index_ = 0;
  current_chunk_index_ = 0;
  last_chunk_info_.reset();
  register_table_.clear();
  module_table_.clear();
  block_table_.clear();
  error_.clear();
}

void trace_reader::reset() {
  if (!stream_.is_open()) {
    return;
  }
  stream_.clear();
  stream_.seekg(0, std::ios::beg);
  header_read_ = false;
  chunk_buffer_.clear();
  chunk_offset_ = 0;
  next_chunk_index_ = 0;
  current_chunk_index_ = 0;
  last_chunk_info_.reset();
  register_table_.clear();
  module_table_.clear();
  block_table_.clear();
  error_.clear();
  read_header();
}

bool trace_reader::read_next(trace_record& record) {
  return read_next(record, nullptr);
}

bool trace_reader::read_next(trace_record& record, trace_record_location* location) {
  if (!error_.empty()) {
    return false;
  }
  if (!header_read_) {
    if (!read_header()) {
      return false;
    }
  }

  if (chunk_offset_ >= chunk_buffer_.size()) {
    chunk_buffer_.clear();
    chunk_offset_ = 0;
    if (!read_chunk()) {
      return false;
    }
  }

  size_t record_offset = chunk_offset_;
  record_header header{};
  if (!read_record_header(header)) {
    return false;
  }

  std::vector<uint8_t> payload(header.size);
  if (header.size > 0) {
    if (!read_bytes(payload.data(), payload.size())) {
      error_ = "truncated record payload";
      return false;
    }
  }

  if (!parse_record(header, payload, record)) {
    if (error_.empty()) {
      error_ = "failed to parse record payload";
    }
    return false;
  }

  if (location) {
    if (record_offset > std::numeric_limits<uint32_t>::max()) {
      error_ = "record offset too large";
      return false;
    }
    location->chunk_index = current_chunk_index_;
    location->record_offset = static_cast<uint32_t>(record_offset);
  }

  return true;
}

bool trace_reader::seek_to_chunk(const trace_chunk_info& chunk, uint32_t chunk_index, uint32_t record_offset) {
  if (!error_.empty()) {
    return false;
  }
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }
  if (!header_read_) {
    stream_.clear();
    stream_.seekg(0, std::ios::beg);
    header_read_ = false;
    if (!read_header()) {
      return false;
    }
  }
  if (!read_chunk_at(chunk.file_offset, chunk_index, &chunk)) {
    return false;
  }
  if (record_offset > chunk_buffer_.size()) {
    error_ = "record offset out of range";
    return false;
  }
  chunk_offset_ = record_offset;
  return true;
}

bool trace_reader::read_header() {
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }

  std::array<uint8_t, 8> magic{};
  if (!read_stream_bytes(magic.data(), magic.size())) {
    if (error_.empty()) {
      error_ = "truncated trace header";
    }
    return false;
  }
  if (std::memcmp(magic.data(), k_trace_magic.data(), k_trace_magic.size()) != 0) {
    error_ = "unexpected trace magic";
    return false;
  }

  uint16_t version = 0;
  uint16_t arch = 0;
  uint32_t pointer_size = 0;
  uint64_t flags = 0;
  uint32_t compression = 0;
  uint32_t chunk_size = 0;

  if (!read_stream_u16(stream_, version) || !read_stream_u16(stream_, arch) ||
      !read_stream_u32(stream_, pointer_size) || !read_stream_u64(stream_, flags) ||
      !read_stream_u32(stream_, compression) || !read_stream_u32(stream_, chunk_size)) {
    error_ = "truncated trace header fields";
    return false;
  }

  if (version != k_trace_version) {
    error_ = "unsupported trace version";
    return false;
  }

  header_.version = version;
  header_.architecture = static_cast<trace_arch>(arch);
  header_.pointer_size = pointer_size;
  header_.flags = flags;
  header_.compression = static_cast<trace_compression>(compression);
  header_.chunk_size = chunk_size;

  if (header_.chunk_size == 0) {
    error_ = "invalid trace chunk size";
    return false;
  }
  if (header_.compression != trace_compression::none && header_.compression != trace_compression::zstd) {
    error_ = "unsupported trace compression mode";
    return false;
  }
#if !defined(W1_REWIND_HAVE_ZSTD)
  if (header_.compression == trace_compression::zstd) {
    error_ = "trace requires zstd support";
    return false;
  }
#endif

  header_read_ = true;
  return true;
}

bool trace_reader::read_chunk() {
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }

  int next = stream_.peek();
  if (next == std::char_traits<char>::eof()) {
    return false;
  }

  std::streampos header_pos = stream_.tellg();
  if (header_pos < 0) {
    error_ = "failed to read chunk header offset";
    return false;
  }
  return read_chunk_at(static_cast<uint64_t>(header_pos), next_chunk_index_, nullptr);
}

bool trace_reader::read_chunk_at(uint64_t file_offset, uint32_t chunk_index, const trace_chunk_info* expected) {
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }

  stream_.clear();
  stream_.seekg(static_cast<std::streamoff>(file_offset), std::ios::beg);
  if (!stream_) {
    error_ = "failed to seek to chunk";
    return false;
  }

  std::streampos header_pos = stream_.tellg();
  if (header_pos < 0) {
    error_ = "failed to read chunk header offset";
    return false;
  }

  uint32_t compressed_size = 0;
  uint32_t uncompressed_size = 0;
  if (!read_stream_u32(stream_, compressed_size) || !read_stream_u32(stream_, uncompressed_size)) {
    if (error_.empty()) {
      error_ = "truncated chunk header";
    }
    return false;
  }

  if (compressed_size == 0 || uncompressed_size == 0) {
    error_ = "invalid chunk header";
    return false;
  }

  if (expected) {
    if (expected->file_offset != static_cast<uint64_t>(header_pos)) {
      error_ = "trace chunk offset mismatch";
      return false;
    }
    if (expected->compressed_size != compressed_size || expected->uncompressed_size != uncompressed_size) {
      error_ = "trace chunk size mismatch";
      return false;
    }
  }

  std::vector<uint8_t> compressed(compressed_size);
  if (!read_stream_bytes(compressed.data(), compressed.size())) {
    if (error_.empty()) {
      error_ = "truncated chunk payload";
    }
    return false;
  }

  last_chunk_info_ = trace_chunk_info{
      static_cast<uint64_t>(header_pos),
      compressed_size,
      uncompressed_size,
  };
  current_chunk_index_ = chunk_index;
  next_chunk_index_ = chunk_index + 1;

  if (header_.compression == trace_compression::none) {
    if (compressed_size != uncompressed_size) {
      error_ = "uncompressed chunk size mismatch";
      return false;
    }
    chunk_buffer_ = std::move(compressed);
    chunk_offset_ = 0;
    return true;
  }

  if (header_.compression != trace_compression::zstd) {
    error_ = "unsupported trace compression mode";
    return false;
  }

#if defined(W1_REWIND_HAVE_ZSTD)
  chunk_buffer_.assign(uncompressed_size, 0);
  size_t result = ZSTD_decompress(
      chunk_buffer_.data(), chunk_buffer_.size(), compressed.data(), compressed.size()
  );
  if (ZSTD_isError(result)) {
    error_ = std::string("zstd decompression failed: ") + ZSTD_getErrorName(result);
    return false;
  }
  if (result != uncompressed_size) {
    error_ = "zstd decompressed size mismatch";
    return false;
  }
  chunk_offset_ = 0;
  return true;
#else
  error_ = "trace requires zstd support";
  return false;
#endif
}

bool trace_reader::read_stream_bytes(void* data, size_t size) {
  if (!w1::rewind::read_stream_bytes(stream_, data, size)) {
    error_ = "truncated trace data";
    return false;
  }
  return true;
}

bool trace_reader::read_bytes(void* data, size_t size) {
  if (size == 0) {
    return true;
  }

  if (chunk_offset_ >= chunk_buffer_.size()) {
    chunk_buffer_.clear();
    chunk_offset_ = 0;
    if (!read_chunk()) {
      return false;
    }
  }

  if (chunk_offset_ + size > chunk_buffer_.size()) {
    error_ = "record spans chunk boundary";
    return false;
  }

  std::memcpy(data, chunk_buffer_.data() + chunk_offset_, size);
  chunk_offset_ += size;
  return true;
}

bool trace_reader::read_record_header(record_header& header) {
  std::array<uint8_t, 8> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }
  trace_buffer_reader reader(std::span<const uint8_t>(buf.data(), buf.size()));
  uint16_t kind_value = 0;
  uint16_t flags = 0;
  uint32_t size = 0;
  if (!reader.read_u16(kind_value) || !reader.read_u16(flags) || !reader.read_u32(size)) {
    return false;
  }

  header.kind = static_cast<record_kind>(kind_value);
  header.flags = flags;
  header.size = size;
  return true;
}

bool trace_reader::parse_record(const record_header& header, const std::vector<uint8_t>& payload, trace_record& record) {
  trace_buffer_reader reader(std::span<const uint8_t>(payload.data(), payload.size()));

  switch (header.kind) {
  case record_kind::register_table: {
    register_table_record out{};
    if (!decode_register_table(reader, out)) {
      return false;
    }
    register_table_ = out.names;
    record = std::move(out);
    return true;
  }
  case record_kind::module_table: {
    module_table_record out{};
    if (!decode_module_table(reader, out)) {
      return false;
    }
    module_table_ = out.modules;
    record = std::move(out);
    return true;
  }
  case record_kind::thread_start: {
    thread_start_record out{};
    if (!decode_thread_start(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::instruction: {
    instruction_record out{};
    if (!decode_instruction(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::block_definition: {
    block_definition_record out{};
    if (!decode_block_definition(reader, out)) {
      return false;
    }
    block_table_.push_back(out);
    record = std::move(out);
    return true;
  }
  case record_kind::block_exec: {
    block_exec_record out{};
    if (!decode_block_exec(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::register_deltas: {
    register_delta_record out{};
    if (!decode_register_deltas(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::memory_access: {
    memory_access_record out{};
    if (!decode_memory_access(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::snapshot: {
    snapshot_record out{};
    if (!decode_snapshot(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::thread_end: {
    thread_end_record out{};
    if (!decode_thread_end(reader, out)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  default:
    error_ = "unknown record kind";
    return false;
  }
}

} // namespace w1::rewind
