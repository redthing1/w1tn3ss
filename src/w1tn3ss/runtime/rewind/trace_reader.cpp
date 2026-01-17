#include "trace_reader.hpp"

#include <array>
#include <cstring>

#if defined(W1_REWIND_HAVE_ZSTD)
#include <zstd.h>
#endif

namespace w1::rewind {
namespace {

class buffer_reader {
public:
  explicit buffer_reader(const std::vector<uint8_t>& data) : data_(data) {}

  bool read_u8(uint8_t& value) { return read_scalar(value); }
  bool read_u16(uint16_t& value) { return read_scalar(value); }
  bool read_u32(uint32_t& value) { return read_scalar(value); }
  bool read_u64(uint64_t& value) { return read_scalar(value); }

  bool read_string(std::string& value) {
    uint16_t len = 0;
    if (!read_u16(len)) {
      return false;
    }
    if (cursor_ + len > data_.size()) {
      return false;
    }
    value.assign(reinterpret_cast<const char*>(data_.data() + cursor_), len);
    cursor_ += len;
    return true;
  }

  bool read_bytes(std::vector<uint8_t>& out, size_t size) {
    if (cursor_ + size > data_.size()) {
      return false;
    }
    auto start = data_.begin() + static_cast<std::vector<uint8_t>::difference_type>(cursor_);
    auto end = start + static_cast<std::vector<uint8_t>::difference_type>(size);
    out.assign(start, end);
    cursor_ += size;
    return true;
  }

  size_t remaining() const { return data_.size() - cursor_; }

private:
  template <typename T> bool read_scalar(T& value) {
    constexpr size_t size = sizeof(T);
    if (cursor_ + size > data_.size()) {
      return false;
    }
    T out = 0;
    for (size_t i = 0; i < size; ++i) {
      out |= static_cast<T>(data_[cursor_ + i]) << (8 * i);
    }
    value = out;
    cursor_ += size;
    return true;
  }

  const std::vector<uint8_t>& data_;
  size_t cursor_ = 0;
};

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
  chunk_buffer_.clear();
  chunk_offset_ = 0;
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
  register_table_.clear();
  module_table_.clear();
  block_table_.clear();
  error_.clear();
  read_header();
}

bool trace_reader::read_next(trace_record& record) {
  if (!error_.empty()) {
    return false;
  }
  if (!header_read_) {
    if (!read_header()) {
      return false;
    }
  }

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

  auto read_stream_u16 = [&](uint16_t& value) {
    std::array<uint8_t, 2> buf{};
    if (!read_stream_bytes(buf.data(), buf.size())) {
      return false;
    }
    value = static_cast<uint16_t>(buf[0] | (static_cast<uint16_t>(buf[1]) << 8));
    return true;
  };
  auto read_stream_u32 = [&](uint32_t& value) {
    std::array<uint8_t, 4> buf{};
    if (!read_stream_bytes(buf.data(), buf.size())) {
      return false;
    }
    value = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
            (static_cast<uint32_t>(buf[2]) << 16) | (static_cast<uint32_t>(buf[3]) << 24);
    return true;
  };
  auto read_stream_u64 = [&](uint64_t& value) {
    std::array<uint8_t, 8> buf{};
    if (!read_stream_bytes(buf.data(), buf.size())) {
      return false;
    }
    value = 0;
    for (size_t i = 0; i < buf.size(); ++i) {
      value |= static_cast<uint64_t>(buf[i]) << (8 * i);
    }
    return true;
  };

  if (!read_stream_u16(version) || !read_stream_u16(arch) || !read_stream_u32(pointer_size) ||
      !read_stream_u64(flags) || !read_stream_u32(compression) || !read_stream_u32(chunk_size)) {
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

  std::array<uint8_t, 8> buf{};
  if (!read_stream_bytes(buf.data(), buf.size())) {
    if (error_.empty()) {
      error_ = "truncated chunk header";
    }
    return false;
  }

  uint32_t compressed_size = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
                             (static_cast<uint32_t>(buf[2]) << 16) | (static_cast<uint32_t>(buf[3]) << 24);
  uint32_t uncompressed_size = static_cast<uint32_t>(buf[4]) | (static_cast<uint32_t>(buf[5]) << 8) |
                               (static_cast<uint32_t>(buf[6]) << 16) | (static_cast<uint32_t>(buf[7]) << 24);

  if (compressed_size == 0 || uncompressed_size == 0) {
    error_ = "invalid chunk header";
    return false;
  }

  std::vector<uint8_t> compressed(compressed_size);
  if (!read_stream_bytes(compressed.data(), compressed.size())) {
    if (error_.empty()) {
      error_ = "truncated chunk payload";
    }
    return false;
  }

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
  stream_.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(size));
  if (stream_.gcount() != static_cast<std::streamsize>(size)) {
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

bool trace_reader::read_u8(uint8_t& value) {
  std::array<uint8_t, 1> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }
  value = buf[0];
  return true;
}

bool trace_reader::read_u16(uint16_t& value) {
  std::array<uint8_t, 2> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }
  value = static_cast<uint16_t>(buf[0] | (static_cast<uint16_t>(buf[1]) << 8));
  return true;
}

bool trace_reader::read_u32(uint32_t& value) {
  std::array<uint8_t, 4> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }
  value = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
          (static_cast<uint32_t>(buf[2]) << 16) | (static_cast<uint32_t>(buf[3]) << 24);
  return true;
}

bool trace_reader::read_u64(uint64_t& value) {
  std::array<uint8_t, 8> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }
  value = 0;
  for (size_t i = 0; i < buf.size(); ++i) {
    value |= static_cast<uint64_t>(buf[i]) << (8 * i);
  }
  return true;
}

bool trace_reader::read_record_header(record_header& header) {
  std::array<uint8_t, 8> buf{};
  if (!read_bytes(buf.data(), buf.size())) {
    return false;
  }

  uint16_t kind_value = static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
  uint16_t flags = static_cast<uint16_t>(buf[2]) | (static_cast<uint16_t>(buf[3]) << 8);
  uint32_t size = static_cast<uint32_t>(buf[4]) | (static_cast<uint32_t>(buf[5]) << 8) |
                  (static_cast<uint32_t>(buf[6]) << 16) | (static_cast<uint32_t>(buf[7]) << 24);

  header.kind = static_cast<record_kind>(kind_value);
  header.flags = flags;
  header.size = size;
  return true;
}

bool trace_reader::parse_record(const record_header& header, const std::vector<uint8_t>& payload, trace_record& record) {
  buffer_reader reader(payload);

  switch (header.kind) {
  case record_kind::register_table: {
    register_table_record out{};
    uint16_t count = 0;
    if (!reader.read_u16(count)) {
      return false;
    }
    out.names.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
      std::string name;
      if (!reader.read_string(name)) {
        return false;
      }
      out.names.push_back(std::move(name));
    }
    register_table_ = out.names;
    record = std::move(out);
    return true;
  }
  case record_kind::module_table: {
    module_table_record out{};
    uint32_t count = 0;
    if (!reader.read_u32(count)) {
      return false;
    }
    out.modules.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      module_record module{};
      if (!reader.read_u64(module.id) || !reader.read_u64(module.base) || !reader.read_u64(module.size) ||
          !reader.read_u32(module.permissions) || !reader.read_string(module.path)) {
        return false;
      }
      out.modules.push_back(std::move(module));
    }
    module_table_ = out.modules;
    record = std::move(out);
    return true;
  }
  case record_kind::thread_start: {
    thread_start_record out{};
    if (!reader.read_u64(out.thread_id) || !reader.read_string(out.name)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::instruction: {
    instruction_record out{};
    if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u64(out.module_id) ||
        !reader.read_u64(out.module_offset) || !reader.read_u32(out.size) || !reader.read_u32(out.flags)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::block_definition: {
    block_definition_record out{};
    if (!reader.read_u64(out.block_id) || !reader.read_u64(out.module_id) || !reader.read_u64(out.module_offset) ||
        !reader.read_u32(out.size)) {
      return false;
    }
    block_table_.push_back(out);
    record = std::move(out);
    return true;
  }
  case record_kind::block_exec: {
    block_exec_record out{};
    if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u64(out.block_id)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::register_deltas: {
    register_delta_record out{};
    uint16_t count = 0;
    if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u16(count)) {
      return false;
    }
    out.deltas.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
      register_delta delta{};
      if (!reader.read_u16(delta.reg_id) || !reader.read_u64(delta.value)) {
        return false;
      }
      out.deltas.push_back(delta);
    }
    record = std::move(out);
    return true;
  }
  case record_kind::memory_access: {
    memory_access_record out{};
    uint8_t kind = 0;
    uint8_t value_known = 0;
    uint8_t value_truncated = 0;
    uint8_t reserved = 0;
    uint32_t data_size = 0;
    if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u8(kind) ||
        !reader.read_u8(value_known) || !reader.read_u8(value_truncated) || !reader.read_u8(reserved) ||
        !reader.read_u64(out.address) || !reader.read_u32(out.size) || !reader.read_u32(data_size)) {
      return false;
    }
    out.kind = static_cast<memory_access_kind>(kind);
    out.value_known = value_known != 0;
    out.value_truncated = value_truncated != 0;
    (void) reserved;
    if (data_size > 0) {
      if (!reader.read_bytes(out.data, data_size)) {
        return false;
      }
    }
    record = std::move(out);
    return true;
  }
  case record_kind::boundary: {
    boundary_record out{};
    uint16_t reg_count = 0;
    uint32_t stack_size = 0;
    if (!reader.read_u64(out.boundary_id) || !reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) ||
        !reader.read_u16(reg_count)) {
      return false;
    }
    out.registers.reserve(reg_count);
    for (uint16_t i = 0; i < reg_count; ++i) {
      register_delta delta{};
      if (!reader.read_u16(delta.reg_id) || !reader.read_u64(delta.value)) {
        return false;
      }
      out.registers.push_back(delta);
    }
    if (!reader.read_u32(stack_size)) {
      return false;
    }
    if (stack_size > 0) {
      if (!reader.read_bytes(out.stack_window, stack_size)) {
        return false;
      }
    }
    if (!reader.read_string(out.reason)) {
      return false;
    }
    record = std::move(out);
    return true;
  }
  case record_kind::thread_end: {
    thread_end_record out{};
    if (!reader.read_u64(out.thread_id)) {
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
