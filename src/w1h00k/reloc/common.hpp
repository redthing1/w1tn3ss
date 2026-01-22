#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace w1::h00k::reloc::detail {

inline constexpr size_t kMaxPatchBytes = 64;

inline int64_t sign_extend(uint64_t value, unsigned bits) {
  if (bits == 0 || bits >= 64) {
    return static_cast<int64_t>(value);
  }
  const uint64_t mask = 1ULL << (bits - 1);
  return static_cast<int64_t>((value ^ mask) - mask);
}

inline bool fits_signed(int64_t value, unsigned bits) {
  if (bits == 0 || bits >= 64) {
    return true;
  }
  const int64_t min = -(1LL << (bits - 1));
  const int64_t max = (1LL << (bits - 1)) - 1;
  return value >= min && value <= max;
}

inline int64_t read_signed_le(const uint8_t* bytes, size_t size) {
  uint64_t value = 0;
  std::memcpy(&value, bytes, size);
  return sign_extend(value, static_cast<unsigned>(size * 8));
}

inline bool write_signed_le(std::vector<uint8_t>& out, size_t offset, size_t size, int64_t value) {
  if (size == 0 || offset + size > out.size()) {
    return false;
  }
  if (size < sizeof(int64_t) && !fits_signed(value, static_cast<unsigned>(size * 8))) {
    return false;
  }
  uint64_t raw = static_cast<uint64_t>(value);
  std::memcpy(out.data() + offset, &raw, size);
  return true;
}

} // namespace w1::h00k::reloc::detail
