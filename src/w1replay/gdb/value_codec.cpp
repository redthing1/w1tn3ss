#include "value_codec.hpp"

#include <limits>

namespace w1replay::gdb {

bool encode_uint64(uint64_t value, size_t size, std::span<std::byte> out, endian order) {
  if (size > sizeof(uint64_t) || out.size() < size) {
    return false;
  }
  uint64_t masked = value;
  if (size < sizeof(uint64_t)) {
    uint64_t mask = (size == 8) ? std::numeric_limits<uint64_t>::max() : ((uint64_t{1} << (size * 8)) - 1);
    masked &= mask;
  }
  for (size_t i = 0; i < size; ++i) {
    size_t shift = (order == endian::little) ? (i * 8) : ((size - 1 - i) * 8);
    out[i] = static_cast<std::byte>((masked >> shift) & 0xff);
  }
  return true;
}

} // namespace w1replay::gdb
