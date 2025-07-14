#include "hex_utils.hpp"
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
  std::string result;
  std::string clean_hex = hex;

  // remove spaces and convert to lowercase
  clean_hex.erase(std::remove_if(clean_hex.begin(), clean_hex.end(), ::isspace), clean_hex.end());
  std::transform(clean_hex.begin(), clean_hex.end(), clean_hex.begin(), ::tolower);

  if (clean_hex.length() % 2 != 0) {
    return "";
  }

  for (size_t i = 0; i < clean_hex.length(); i += 2) {
    char hex_byte[3] = {clean_hex[i], clean_hex[i + 1], '\0'};

    if (!is_hex_digit(hex_byte[0]) || !is_hex_digit(hex_byte[1])) {
      return "";
    }

    uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
    result.push_back(static_cast<char>(byte));
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

} // namespace p1ll::utils