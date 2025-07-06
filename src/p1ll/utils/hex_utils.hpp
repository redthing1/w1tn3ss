#pragma once

#include <string>
#include <vector>
#include <cstdint>

// forward declarations
namespace p1ll::core {
struct compiled_signature;
}

namespace p1ll::utils {

// string to hex conversion
std::string str2hex(const std::string& str);
std::string hex2str(const std::string& hex);

// pattern validation and parsing
bool is_valid_hex_pattern(const std::string& pattern);
std::vector<uint8_t> parse_hex_bytes(const std::string& hex);
std::string strip_comments(const std::string& pattern);
std::string normalize_hex_pattern(const std::string& pattern);

// address formatting
std::string format_address(uint64_t address);
std::string format_bytes(const std::vector<uint8_t>& bytes);

// hex digit utilities
bool is_hex_digit(char c);
uint8_t parse_hex_digit(char c);
std::string to_hex_string(uint8_t byte);

// pattern visualization
std::string format_compiled_signature(const core::compiled_signature& sig);
std::string format_memory_range(uint64_t start_addr, uint64_t end_addr);
std::string format_memory_region(uint64_t start_addr, uint64_t size, const std::string& name);
std::string format_hex_bytes(const uint8_t* data, size_t size, size_t max_bytes = 16);

} // namespace p1ll::utils