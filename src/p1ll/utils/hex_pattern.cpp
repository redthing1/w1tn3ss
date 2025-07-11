#include "hex_pattern.hpp"
#include "hex_utils.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace p1ll::utils {

std::string strip_comments_hex_pattern(const std::string& pattern);

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
    if ((first == '?' && second == '?') || (p1ll::utils::is_hex_digit(first) && p1ll::utils::is_hex_digit(second))) {
      continue;
    } else {
      return false;
    }
  }

  return true;
}

std::vector<uint8_t> parse_hex_pattern(const std::string& hex) {
  auto log = redlog::get_logger("p1ll.hex_pattern");

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

std::string strip_comments_hex_pattern(const std::string& pattern) {
  std::string result;
  std::istringstream stream(pattern);
  std::string line;

  while (std::getline(stream, line)) {
    // find the first comment delimiter
    size_t comment_pos = std::string::npos;

    // check for -- comment
    size_t pos = line.find("--");
    if (pos != std::string::npos) {
      comment_pos = pos;
    }

    // check for // comment
    pos = line.find("//");
    if (pos != std::string::npos && pos < comment_pos) {
      comment_pos = pos;
    }

    // check for # comment
    pos = line.find('#');
    if (pos != std::string::npos && pos < comment_pos) {
      comment_pos = pos;
    }

    // check for ; comment
    pos = line.find(';');
    if (pos != std::string::npos && pos < comment_pos) {
      comment_pos = pos;
    }

    // extract the part before the comment
    if (comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }

    // add the line to result (with a space separator if needed)
    if (!result.empty() && !line.empty()) {
      result += " ";
    }
    result += line;
  }

  return result;
}

std::string normalize_hex_pattern(const std::string& pattern) {
  // first strip comments
  std::string stripped = strip_comments_hex_pattern(pattern);

  std::string result;
  result.reserve(stripped.length());

  for (char c : stripped) {
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

// pattern visualization
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