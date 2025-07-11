#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace p1ll::utils {

// string to hex conversion
std::string str2hex(const std::string& str);
std::string hex2str(const std::string& hex);

// address formatting
std::string format_address(uint64_t address);
std::string format_bytes(const std::vector<uint8_t>& bytes);

// hex digit utilities
bool is_hex_digit(char c);
uint8_t parse_hex_digit(char c);
std::string to_hex_string(uint8_t byte);

} // namespace p1ll::utils