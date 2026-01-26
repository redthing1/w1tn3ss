#include "trace_reader.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

#if defined(WITNESS_REWIND_HAVE_ZSTD)
#include <zstd.h>
#endif

#include "w1rewind/format/trace_codec.hpp"
#include "w1rewind/format/trace_io.hpp"

namespace w1::rewind {

namespace {
constexpr uint64_t k_footer_size = sizeof(k_trace_footer_magic) + sizeof(uint16_t) + sizeof(uint16_t) +
                                   sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t);
} // namespace

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
  has_chunk_directory_ = false;
  header_end_offset_ = 0;
  chunk_buffer_.clear();
  chunk_offset_ = 0;
  next_chunk_index_ = 0;
  current_chunk_index_ = 0;
  last_chunk_info_.reset();
  chunks_.clear();
  error_.clear();
}

void trace_reader::reset() {
  if (!stream_.is_open()) {
    return;
  }
  stream_.clear();
  stream_.seekg(0, std::ios::beg);
  header_read_ = false;
  has_chunk_directory_ = false;
  header_end_offset_ = 0;
  chunk_buffer_.clear();
  chunk_offset_ = 0;
  next_chunk_index_ = 0;
  current_chunk_index_ = 0;
  last_chunk_info_.reset();
  chunks_.clear();
  error_.clear();
  read_header();
}

bool trace_reader::read_next(trace_record& record) { return read_next(record, nullptr); }

bool trace_reader::read_next(trace_record& record, trace_record_location* location) {
  if (!error_.empty()) {
    return false;
  }
  if (!header_read_) {
    if (!read_header()) {
      return false;
    }
  }

  while (true) {
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

    std::vector<uint8_t> payload(header.payload_size);
    if (header.payload_size > 0) {
      if (!read_bytes(payload.data(), payload.size())) {
        error_ = "truncated record payload";
        return false;
      }
    }

    if (parse_record(header, payload, record)) {
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

    if (!error_.empty()) {
      return false;
    }
    // Unknown record type or version: skip and continue.
  }
}

bool trace_reader::seek_to_location(const trace_record_location& location) {
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

  if (location.chunk_index == current_chunk_index_ && last_chunk_info_.has_value()) {
    return seek_to_chunk(*last_chunk_info_, location.chunk_index, location.record_offset);
  }
  if (!ensure_chunk_info(location.chunk_index)) {
    return false;
  }
  if (location.chunk_index >= chunks_.size()) {
    error_ = "trace chunk not cached";
    return false;
  }
  return seek_to_chunk(chunks_[location.chunk_index], location.chunk_index, location.record_offset);
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
  uint16_t header_size = 0;
  uint32_t flags = 0;
  std::array<uint8_t, 16> uuid{};
  uint32_t default_chunk_size = 0;
  uint32_t reserved = 0;

  if (!read_stream_u16(stream_, version) || !read_stream_u16(stream_, header_size) ||
      !read_stream_u32(stream_, flags) || !read_stream_bytes(uuid.data(), uuid.size()) ||
      !read_stream_u32(stream_, default_chunk_size) || !read_stream_u32(stream_, reserved)) {
    error_ = "truncated trace header fields";
    return false;
  }

  if (version != k_trace_version) {
    error_ = "unsupported trace version";
    return false;
  }

  header_.version = version;
  header_.header_size = header_size;
  header_.flags = flags;
  header_.trace_uuid = uuid;
  header_.default_chunk_size = default_chunk_size;
  header_.reserved = reserved;

  if (header_.header_size < sizeof(file_header)) {
    error_ = "trace header size invalid";
    return false;
  }

  // Skip any extra header bytes if header_size > current.
  if (header_.header_size > sizeof(file_header)) {
    uint64_t extra = header_.header_size - sizeof(file_header);
    stream_.seekg(static_cast<std::streamoff>(extra), std::ios::cur);
    if (!stream_) {
      error_ = "failed to skip header padding";
      return false;
    }
  }

  auto header_end = stream_.tellg();
  if (header_end >= 0) {
    header_end_offset_ = static_cast<uint64_t>(header_end);
  }

  header_read_ = true;
  if (!read_footer()) {
    // Footer is optional; do not fail if missing.
    error_.clear();
  }
  if (header_end_offset_ != 0) {
    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(header_end_offset_), std::ios::beg);
    if (!stream_) {
      error_ = "failed to seek to trace data";
      return false;
    }
  }
  return true;
}

bool trace_reader::read_footer() {
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }

  stream_.clear();
  stream_.seekg(0, std::ios::end);
  auto end_pos = stream_.tellg();
  if (end_pos <= 0) {
    return false;
  }
  uint64_t file_size = static_cast<uint64_t>(end_pos);
  if (file_size < k_footer_size) {
    return false;
  }

  stream_.seekg(static_cast<std::streamoff>(file_size - k_footer_size), std::ios::beg);
  if (!stream_) {
    return false;
  }

  std::array<uint8_t, 8> magic{};
  if (!read_stream_bytes(magic.data(), magic.size())) {
    return false;
  }
  if (std::memcmp(magic.data(), k_trace_footer_magic.data(), k_trace_footer_magic.size()) != 0) {
    return false;
  }

  uint16_t version = 0;
  uint16_t footer_size = 0;
  uint32_t chunk_count = 0;
  uint64_t directory_offset = 0;
  uint64_t directory_size = 0;
  uint32_t reserved = 0;

  if (!read_stream_u16(stream_, version) || !read_stream_u16(stream_, footer_size) ||
      !read_stream_u32(stream_, chunk_count) || !read_stream_u64(stream_, directory_offset) ||
      !read_stream_u64(stream_, directory_size) || !read_stream_u32(stream_, reserved)) {
    return false;
  }

  if (version != k_trace_version) {
    return false;
  }

  if (footer_size < k_footer_size) {
    return false;
  }
  if (directory_size != static_cast<uint64_t>(chunk_count) * k_chunk_dir_entry_size) {
    return false;
  }

  if (directory_offset + directory_size > file_size) {
    return false;
  }

  chunks_.clear();
  chunks_.reserve(chunk_count);
  stream_.seekg(static_cast<std::streamoff>(directory_offset), std::ios::beg);
  if (!stream_) {
    return false;
  }

  for (uint32_t i = 0; i < chunk_count; ++i) {
    chunk_dir_entry entry{};
    if (!read_stream_u64(stream_, entry.chunk_file_offset) || !read_stream_u32(stream_, entry.compressed_size) ||
        !read_stream_u32(stream_, entry.uncompressed_size)) {
      return false;
    }
    uint16_t codec = 0;
    if (!read_stream_u16(stream_, codec) || !read_stream_u16(stream_, entry.flags)) {
      return false;
    }
    entry.codec = static_cast<compression>(codec);
    trace_chunk_info info{};
    info.file_offset = entry.chunk_file_offset;
    info.compressed_size = entry.compressed_size;
    info.uncompressed_size = entry.uncompressed_size;
    info.codec = entry.codec;
    info.flags = entry.flags;
    chunks_.push_back(info);
  }

  has_chunk_directory_ = true;
  return true;
}

bool trace_reader::ensure_chunk_info(uint32_t chunk_index) {
  if (chunks_.size() > chunk_index) {
    return true;
  }
  if (has_chunk_directory_) {
    return false;
  }
  if (!header_read_) {
    if (!read_header()) {
      return false;
    }
  }
  if (header_end_offset_ == 0) {
    error_ = "trace header offset unknown";
    return false;
  }
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }

  uint32_t start_index = static_cast<uint32_t>(chunks_.size());
  uint64_t offset = header_end_offset_;
  if (start_index > 0) {
    const auto& last = chunks_.back();
    offset = last.file_offset + sizeof(chunk_header) + last.compressed_size;
  }

  stream_.clear();
  stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!stream_) {
    error_ = "failed to seek to chunk";
    return false;
  }

  for (uint32_t current = start_index; current <= chunk_index; ++current) {
    std::streampos header_pos = stream_.tellg();
    if (header_pos < 0) {
      error_ = "failed to read chunk header offset";
      return false;
    }

    uint32_t compressed_size = 0;
    uint32_t uncompressed_size = 0;
    uint16_t codec = 0;
    uint16_t flags = 0;
    uint32_t reserved = 0;
    if (!read_stream_u32(stream_, compressed_size) || !read_stream_u32(stream_, uncompressed_size) ||
        !read_stream_u16(stream_, codec) || !read_stream_u16(stream_, flags) || !read_stream_u32(stream_, reserved)) {
      if (error_.empty()) {
        error_ = "truncated chunk header";
      }
      return false;
    }
    if (compressed_size == 0 || uncompressed_size == 0) {
      error_ = "invalid chunk header";
      return false;
    }

    if (chunks_.size() <= current) {
      chunks_.resize(current + 1);
    }
    chunks_[current] = trace_chunk_info{
        static_cast<uint64_t>(header_pos), compressed_size, uncompressed_size, static_cast<compression>(codec), flags,
    };

    stream_.seekg(static_cast<std::streamoff>(compressed_size), std::ios::cur);
    if (!stream_) {
      error_ = "failed to seek to next chunk";
      return false;
    }
  }

  return true;
}

bool trace_reader::read_chunk() {
  if (!stream_.is_open()) {
    error_ = "trace file not open";
    return false;
  }

  if (has_chunk_directory_) {
    if (next_chunk_index_ >= chunks_.size()) {
      return false;
    }
    const auto& info = chunks_[next_chunk_index_];
    return read_chunk_at(info.file_offset, next_chunk_index_, &info);
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
  uint16_t codec = 0;
  uint16_t flags = 0;
  uint32_t reserved = 0;
  if (!read_stream_u32(stream_, compressed_size) || !read_stream_u32(stream_, uncompressed_size) ||
      !read_stream_u16(stream_, codec) || !read_stream_u16(stream_, flags) || !read_stream_u32(stream_, reserved)) {
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
    if (expected->compressed_size != compressed_size || expected->uncompressed_size != uncompressed_size ||
        expected->codec != static_cast<compression>(codec) || expected->flags != flags) {
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
      static_cast<uint64_t>(header_pos), compressed_size, uncompressed_size, static_cast<compression>(codec), flags,
  };
  if (chunks_.size() <= chunk_index) {
    chunks_.resize(chunk_index + 1);
  }
  chunks_[chunk_index] = *last_chunk_info_;
  current_chunk_index_ = chunk_index;
  next_chunk_index_ = chunk_index + 1;

  if (static_cast<compression>(codec) == compression::none) {
    if (compressed_size != uncompressed_size) {
      error_ = "uncompressed chunk size mismatch";
      return false;
    }
    chunk_buffer_ = std::move(compressed);
    chunk_offset_ = 0;
    return true;
  }

  if (static_cast<compression>(codec) != compression::zstd) {
    error_ = "unsupported trace compression mode";
    return false;
  }

#if defined(WITNESS_REWIND_HAVE_ZSTD)
  chunk_buffer_.assign(uncompressed_size, 0);
  size_t result = ZSTD_decompress(chunk_buffer_.data(), chunk_buffer_.size(), compressed.data(), compressed.size());
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
  std::array<uint8_t, sizeof(record_header)> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }
  trace_buffer_reader reader(std::span<const uint8_t>(buf.data(), buf.size()));
  if (!reader.read_u32(header.type_id) || !reader.read_u16(header.version) || !reader.read_u16(header.flags) ||
      !reader.read_u32(header.payload_size)) {
    return false;
  }
  return true;
}

bool trace_reader::parse_record(
    const record_header& header, const std::vector<uint8_t>& payload, trace_record& record
) {
  if (header.version != 1) {
    return false;
  }
  trace_buffer_reader reader(std::span<const uint8_t>(payload.data(), payload.size()));

  switch (header.type_id) {
  case k_record_type_dictionary: {
    record_type_dictionary_record out{};
    if (!decode_record_type_dictionary(reader, out)) {
      error_ = "failed to decode record type dictionary";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_arch_descriptor: {
    arch_descriptor_record out{};
    if (!decode_arch_descriptor(reader, out)) {
      error_ = "failed to decode arch descriptor";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_environment: {
    environment_record out{};
    if (!decode_environment(reader, out)) {
      error_ = "failed to decode environment";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_address_space: {
    address_space_record out{};
    if (!decode_address_space(reader, out)) {
      error_ = "failed to decode address space";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_register_file: {
    register_file_record out{};
    if (!decode_register_file(reader, out)) {
      error_ = "failed to decode register file";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_image: {
    image_record out{};
    if (!decode_image(reader, out)) {
      error_ = "failed to decode image";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_image_metadata: {
    image_metadata_record out{};
    if (!decode_image_metadata(reader, out)) {
      error_ = "failed to decode image metadata";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_image_blob: {
    image_blob_record out{};
    if (!decode_image_blob(reader, out)) {
      error_ = "failed to decode image blob";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_mapping: {
    mapping_record out{};
    if (!decode_mapping(reader, out)) {
      error_ = "failed to decode mapping";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_thread_start: {
    thread_start_record out{};
    if (!decode_thread_start(reader, out)) {
      error_ = "failed to decode thread start";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_thread_end: {
    thread_end_record out{};
    if (!decode_thread_end(reader, out)) {
      error_ = "failed to decode thread end";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_flow_instruction: {
    flow_instruction_record out{};
    if (!decode_flow_instruction(reader, out)) {
      error_ = "failed to decode flow instruction";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_block_definition: {
    block_definition_record out{};
    if (!decode_block_definition(reader, out)) {
      error_ = "failed to decode block definition";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_block_exec: {
    block_exec_record out{};
    if (!decode_block_exec(reader, out)) {
      error_ = "failed to decode block exec";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_reg_write: {
    reg_write_record out{};
    if (!decode_reg_write(reader, out)) {
      error_ = "failed to decode reg write";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_mem_access: {
    mem_access_record out{};
    if (!decode_mem_access(reader, out)) {
      error_ = "failed to decode mem access";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_snapshot: {
    snapshot_record out{};
    if (!decode_snapshot(reader, out)) {
      error_ = "failed to decode snapshot";
      return false;
    }
    record = std::move(out);
    return true;
  }
  case k_record_type_meta: {
    meta_record out{};
    if (!decode_meta(reader, out)) {
      error_ = "failed to decode meta";
      return false;
    }
    record = std::move(out);
    return true;
  }
  default:
    return false;
  }
}

} // namespace w1::rewind
