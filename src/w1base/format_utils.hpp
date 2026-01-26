#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <span>
#include <sstream>
#include <string>

namespace w1::util {

inline std::string format_number(uint64_t value) {
  std::string out = std::to_string(value);
  for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(out.size()) - 3; i > 0; i -= 3) {
    out.insert(static_cast<size_t>(i), ",");
  }
  return out;
}

inline std::string format_decimal(double value, int precision) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  std::string text = out.str();
  if (precision > 0) {
    while (!text.empty() && text.back() == '0') {
      text.pop_back();
    }
    if (!text.empty() && text.back() == '.') {
      text.pop_back();
    }
  }
  if (text.empty()) {
    return "0";
  }
  return text;
}

inline std::string format_bytes(uint64_t bytes, int precision = 1) {
  static constexpr const char* suffixes[] = {"B", "KB", "MB", "GB", "TB", "PB"};
  constexpr size_t suffix_count = sizeof(suffixes) / sizeof(suffixes[0]);
  double value = static_cast<double>(bytes);
  size_t suffix_index = 0;
  while (value >= 1024.0 && suffix_index + 1 < suffix_count) {
    value /= 1024.0;
    ++suffix_index;
  }
  if (suffix_index == 0) {
    return format_number(bytes) + " B";
  }
  return format_decimal(value, precision) + " " + suffixes[suffix_index];
}

inline std::string format_hex(uint64_t value, size_t width = 0, bool prefix = true) {
  std::ostringstream out;
  if (prefix) {
    out << "0x";
  }
  out << std::hex;
  if (width > 0) {
    out << std::setw(static_cast<int>(width)) << std::setfill('0');
  }
  out << value;
  return out.str();
}

inline std::string format_address(uint64_t address) {
  return format_hex(address, 0, true);
}

inline std::string format_hex_byte(std::byte value, bool known = true) {
  if (!known) {
    return "??";
  }
  std::ostringstream out;
  out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<uint8_t>(value));
  return out.str();
}

inline std::string format_hex_bytes(std::span<const std::byte> bytes, char separator = ' ') {
  std::ostringstream out;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      out << separator;
    }
    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<uint8_t>(bytes[i]));
  }
  return out.str();
}

inline std::string format_permissions(bool read, bool write, bool exec) {
  std::string perms = "---";
  if (read) {
    perms[0] = 'r';
  }
  if (write) {
    perms[1] = 'w';
  }
  if (exec) {
    perms[2] = 'x';
  }
  return perms;
}

inline std::string format_bool(bool value) { return value ? "true" : "false"; }

} // namespace w1::util
