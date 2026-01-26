#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <istream>
#include <limits>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace w1::rewind {

class trace_buffer_writer {
public:
  explicit trace_buffer_writer(std::vector<uint8_t>& out) : out_(out) {}

  void write_u8(uint8_t value) { out_.push_back(value); }

  void write_u16(uint16_t value) {
    out_.push_back(static_cast<uint8_t>(value & 0xFFu));
    out_.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
  }

  void write_u32(uint32_t value) {
    for (size_t i = 0; i < 4; ++i) {
      out_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
    }
  }

  void write_u64(uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
      out_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFFu));
    }
  }

  void write_bytes(const void* data, size_t size) {
    if (size == 0) {
      return;
    }
    const auto* bytes = static_cast<const uint8_t*>(data);
    out_.insert(out_.end(), bytes, bytes + static_cast<std::ptrdiff_t>(size));
  }

  void write_bytes(std::span<const uint8_t> data) { write_bytes(data.data(), data.size()); }

  bool write_string(std::string_view value) {
    if (value.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
      return false;
    }
    write_u32(static_cast<uint32_t>(value.size()));
    if (!value.empty()) {
      write_bytes(value.data(), value.size());
    }
    return true;
  }

private:
  std::vector<uint8_t>& out_;
};

class trace_buffer_reader {
public:
  explicit trace_buffer_reader(std::span<const uint8_t> data) : data_(data) {}

  bool read_u8(uint8_t& value) { return read_scalar(value); }
  bool read_u16(uint16_t& value) { return read_scalar(value); }
  bool read_u32(uint32_t& value) { return read_scalar(value); }
  bool read_u64(uint64_t& value) { return read_scalar(value); }

  bool read_string(std::string& value) {
    uint32_t len = 0;
    if (!read_u32(len)) {
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
    auto start = data_.begin() + static_cast<std::ptrdiff_t>(cursor_);
    auto end = start + static_cast<std::ptrdiff_t>(size);
    out.assign(start, end);
    cursor_ += size;
    return true;
  }

  bool read_bytes(void* out, size_t size) {
    if (cursor_ + size > data_.size()) {
      return false;
    }
    if (size == 0) {
      return true;
    }
    std::memcpy(out, data_.data() + cursor_, size);
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

  std::span<const uint8_t> data_;
  size_t cursor_ = 0;
};

inline bool read_stream_bytes(std::istream& in, void* data, size_t size) {
  if (size == 0) {
    return true;
  }
  in.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(size));
  return in.gcount() == static_cast<std::streamsize>(size);
}

inline bool read_stream_u16(std::istream& in, uint16_t& value) {
  std::array<uint8_t, 2> buf{};
  if (!read_stream_bytes(in, buf.data(), buf.size())) {
    return false;
  }
  value = static_cast<uint16_t>(buf[0] | (static_cast<uint16_t>(buf[1]) << 8));
  return true;
}

inline bool read_stream_u32(std::istream& in, uint32_t& value) {
  std::array<uint8_t, 4> buf{};
  if (!read_stream_bytes(in, buf.data(), buf.size())) {
    return false;
  }
  value = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) | (static_cast<uint32_t>(buf[2]) << 16) |
          (static_cast<uint32_t>(buf[3]) << 24);
  return true;
}

inline bool read_stream_u64(std::istream& in, uint64_t& value) {
  std::array<uint8_t, 8> buf{};
  if (!read_stream_bytes(in, buf.data(), buf.size())) {
    return false;
  }
  value = 0;
  for (size_t i = 0; i < buf.size(); ++i) {
    value |= static_cast<uint64_t>(buf[i]) << (8 * i);
  }
  return true;
}

inline bool write_stream_bytes(std::ostream& out, const void* data, size_t size) {
  if (size == 0) {
    return true;
  }
  out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
  return out.good();
}

inline bool write_stream_u16(std::ostream& out, uint16_t value) {
  std::array<uint8_t, 2> buf{};
  buf[0] = static_cast<uint8_t>(value & 0xFFu);
  buf[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  return write_stream_bytes(out, buf.data(), buf.size());
}

inline bool write_stream_u32(std::ostream& out, uint32_t value) {
  std::array<uint8_t, 4> buf{};
  for (size_t i = 0; i < buf.size(); ++i) {
    buf[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
  }
  return write_stream_bytes(out, buf.data(), buf.size());
}

inline bool write_stream_u64(std::ostream& out, uint64_t value) {
  std::array<uint8_t, 8> buf{};
  for (size_t i = 0; i < buf.size(); ++i) {
    buf[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFFu);
  }
  return write_stream_bytes(out, buf.data(), buf.size());
}

} // namespace w1::rewind
