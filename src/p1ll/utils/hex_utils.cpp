#include "hex_utils.hpp"
#include "../core/types.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace p1ll::utils {

std::string str2hex(const std::string& str) {
  std::ostringstream oss;
  for (unsigned char c : str) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  }
  return oss.str();
}

std::string hex2str(const std::string& hex) {
  auto log = redlog::get_logger("p1ll.hex_utils");

  std::string result;
  std::string clean_hex = normalize_hex_pattern(hex);

  if (clean_hex.length() % 2 != 0) {
    log.err("hex string has odd length", redlog::field("hex", hex));
    return "";
  }

  for (size_t i = 0; i < clean_hex.length(); i += 2) {
    char hex_byte[3] = {clean_hex[i], clean_hex[i + 1], '\0'};

    if (!is_hex_digit(hex_byte[0]) || !is_hex_digit(hex_byte[1])) {
      log.err("invalid hex digit", redlog::field("byte", hex_byte));
      return "";
    }

    uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
    result.push_back(static_cast<char>(byte));
  }

  return result;
}

bool is_valid_hex_pattern(const std::string& pattern) {
  std::string normalized = normalize_hex_pattern(pattern);

  // check if length is even (each byte needs 2 hex digits or ?? wildcard)
  if (normalized.length() % 2 != 0) {
    return false;
  }

  // validate each byte position
  for (size_t i = 0; i < normalized.length(); i += 2) {
    char first = normalized[i];
    char second = normalized[i + 1];

    // either both are hex digits or both are wildcards
    if ((first == '?' && second == '?') || (is_hex_digit(first) && is_hex_digit(second))) {
      continue;
    } else {
      return false;
    }
  }

  return true;
}

std::vector<uint8_t> parse_hex_bytes(const std::string& hex) {
  auto log = redlog::get_logger("p1ll.hex_utils");

  std::vector<uint8_t> bytes;
  std::string clean_hex = normalize_hex_pattern(hex);

  if (!is_valid_hex_pattern(clean_hex)) {
    log.err("invalid hex pattern", redlog::field("pattern", hex));
    return bytes;
  }

  for (size_t i = 0; i < clean_hex.length(); i += 2) {
    char hex_byte[3] = {clean_hex[i], clean_hex[i + 1], '\0'};

    if (hex_byte[0] == '?' && hex_byte[1] == '?') {
      // wildcard byte, use 0x00 as placeholder
      bytes.push_back(0x00);
    } else {
      uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
      bytes.push_back(byte);
    }
  }

  return bytes;
}

std::string normalize_hex_pattern(const std::string& pattern) {
  std::string result;
  result.reserve(pattern.length());

  for (char c : pattern) {
    if (std::isspace(c)) {
      // skip whitespace
      continue;
    } else if (std::isalpha(c)) {
      // convert to lowercase
      result.push_back(std::tolower(c));
    } else {
      // numbers, question marks, etc.
      result.push_back(c);
    }
  }

  return result;
}

std::string format_address(uint64_t address) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << address;
  return oss.str();
}

std::string format_bytes(const std::vector<uint8_t>& bytes) {
  std::ostringstream oss;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      oss << " ";
    }
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
  }
  return oss.str();
}

bool is_hex_digit(char c) { return std::isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

uint8_t parse_hex_digit(char c) {
  if (std::isdigit(c)) {
    return static_cast<uint8_t>(c - '0');
  } else if (c >= 'a' && c <= 'f') {
    return static_cast<uint8_t>(c - 'a' + 10);
  } else if (c >= 'A' && c <= 'F') {
    return static_cast<uint8_t>(c - 'A' + 10);
  }
  return 0; // invalid
}

std::string to_hex_string(uint8_t byte) {
  std::ostringstream oss;
  oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  return oss.str();
}

// pattern visualization
std::string format_compiled_signature(const core::compiled_signature& sig) {
  std::ostringstream result;
  for (size_t i = 0; i < sig.pattern.size(); i++) {
    if (sig.mask[i]) {
      // exact byte (lowercase hex)
      result << std::hex << std::setw(2) << std::setfill('0') << std::nouppercase << static_cast<int>(sig.pattern[i]);
    } else {
      // wildcard
      result << "??";
    }
    if (i < sig.pattern.size() - 1) {
      result << " ";
    }
  }
  return result.str();
}

std::string format_memory_range(uint64_t start_addr, uint64_t end_addr) {
  size_t range_size = static_cast<size_t>(end_addr - start_addr);
  std::ostringstream oss;
  oss << "range([$" << std::hex << std::setw(16) << std::setfill('0') << std::nouppercase << start_addr << "-$"
      << std::setw(16) << std::setfill('0') << end_addr << "], sz=" << std::dec << range_size << ")";
  return oss.str();
}

std::string format_memory_region(uint64_t start_addr, uint64_t size, const std::string& name) {
  uint64_t end_addr = start_addr + size;
  std::ostringstream oss;
  oss << "region([$" << std::hex << std::setw(16) << std::setfill('0') << std::nouppercase << start_addr << "-$"
      << std::setw(16) << std::setfill('0') << end_addr << "], sz=" << std::dec << size;
  if (!name.empty()) {
    oss << ", name=" << name;
  }
  oss << ")";
  return oss.str();
}

std::string format_hex_bytes(const uint8_t* data, size_t size, size_t max_bytes) {
  std::ostringstream oss;
  size_t display_size = std::min(size, max_bytes);

  for (size_t i = 0; i < display_size; i++) {
    oss << std::hex << std::setw(2) << std::setfill('0') << std::nouppercase << static_cast<int>(data[i]);
    if (i < display_size - 1) {
      oss << " ";
    }
  }

  if (size > max_bytes) {
    oss << " ... (+" << (size - max_bytes) << " bytes)";
  }

  return oss.str();
}

} // namespace p1ll::utils