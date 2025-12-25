#include "pattern.hpp"
#include "utils/hex_pattern.hpp"
#include "utils/hex_utils.hpp"
#include <string>

namespace p1ll::engine {

namespace {

result<pattern> parse_pattern_impl(std::string_view hex, error_code invalid_code) {
  std::string hex_str(hex);
  if (!p1ll::utils::is_valid_hex_pattern(hex_str)) {
    return error_result<pattern>(invalid_code, "invalid hex pattern");
  }

  std::string normalized = p1ll::utils::normalize_hex_pattern(hex_str);
  pattern parsed;
  parsed.bytes.reserve(normalized.size() / 2);
  parsed.mask.reserve(normalized.size() / 2);

  for (size_t i = 0; i < normalized.size(); i += 2) {
    char first = normalized[i];
    char second = normalized[i + 1];
    if (first == '?' && second == '?') {
      parsed.bytes.push_back(0x00);
      parsed.mask.push_back(0);
      continue;
    }

    uint8_t high = p1ll::utils::parse_hex_digit(first);
    uint8_t low = p1ll::utils::parse_hex_digit(second);
    parsed.bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    parsed.mask.push_back(1);
  }

  return ok_result(parsed);
}

} // namespace

result<pattern> parse_signature(std::string_view hex) { return parse_pattern_impl(hex, error_code::invalid_pattern); }

result<pattern> parse_patch(std::string_view hex) { return parse_pattern_impl(hex, error_code::invalid_pattern); }

} // namespace p1ll::engine
