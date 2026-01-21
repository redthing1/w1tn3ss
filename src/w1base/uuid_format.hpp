#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace w1::util {

constexpr size_t k_uuid_byte_count = 16;

bool is_all_zero_uuid(std::span<const uint8_t, k_uuid_byte_count> bytes);
std::string format_uuid(std::span<const uint8_t, k_uuid_byte_count> bytes);

inline bool is_all_zero_uuid(const std::array<uint8_t, k_uuid_byte_count>& bytes) {
  return is_all_zero_uuid(std::span<const uint8_t, k_uuid_byte_count>(bytes));
}

inline std::string format_uuid(const std::array<uint8_t, k_uuid_byte_count>& bytes) {
  return format_uuid(std::span<const uint8_t, k_uuid_byte_count>(bytes));
}

} // namespace w1::util
