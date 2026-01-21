#include "uuid_format.hpp"

namespace w1::util {

bool is_all_zero_uuid(std::span<const uint8_t, k_uuid_byte_count> bytes) {
  for (uint8_t value : bytes) {
    if (value != 0) {
      return false;
    }
  }
  return true;
}

std::string format_uuid(std::span<const uint8_t, k_uuid_byte_count> bytes) {
  static constexpr char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(36);
  auto append_byte = [&](uint8_t value) {
    out.push_back(k_hex[(value >> 4) & 0x0f]);
    out.push_back(k_hex[value & 0x0f]);
  };
  size_t idx = 0;
  const size_t groups[] = {4, 2, 2, 2, 6};
  for (size_t group = 0; group < 5; ++group) {
    if (group > 0) {
      out.push_back('-');
    }
    for (size_t i = 0; i < groups[group]; ++i) {
      append_byte(bytes[idx++]);
    }
  }
  return out;
}

} // namespace w1::util
