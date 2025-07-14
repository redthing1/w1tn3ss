#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace p1ll::utils {

// pattern validation and parsing
bool is_valid_hex_pattern(const std::string& pattern);
std::vector<uint8_t> parse_hex_pattern(const std::string& hex);
std::string normalize_hex_pattern(const std::string& pattern);

// pattern visualization
std::string format_memory_range(uint64_t start_addr, uint64_t end_addr);
std::string format_memory_region(uint64_t start_addr, uint64_t size, const std::string& name);
std::string format_hex_bytes(const uint8_t* data, size_t size, size_t max_bytes = 16);

} // namespace p1ll::utils