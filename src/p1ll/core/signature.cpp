#include "signature.hpp"
#include "../utils/hex_utils.hpp"
#include <redlog.hpp>
#include <sstream>
#include <algorithm>

namespace p1ll::core {

compiled_signature compile_signature(const signature_pattern& pattern) {
  auto log = redlog::get_logger("p1ll.signature");

  compiled_signature result;

  if (!validate_signature_pattern(pattern)) {
    log.err("invalid signature pattern", redlog::field("pattern", pattern));
    return result;
  }

  std::string normalized = utils::normalize_hex_pattern(pattern);

  // reserve space for efficiency
  size_t byte_count = normalized.length() / 2;
  result.pattern.reserve(byte_count);
  result.mask.reserve(byte_count);

  for (size_t i = 0; i < normalized.length(); i += 2) {
    char first = normalized[i];
    char second = normalized[i + 1];

    if (first == '?' && second == '?') {
      // wildcard byte
      result.pattern.push_back(0x00); // placeholder
      result.mask.push_back(false);   // wildcard
    } else {
      // exact byte
      char hex_byte[3] = {first, second, '\0'};
      uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
      result.pattern.push_back(byte);
      result.mask.push_back(true); // exact match
    }
  }

  auto wildcard_count = std::count(result.mask.begin(), result.mask.end(), false);
  std::string visual_pattern = utils::format_compiled_signature(result);

  log.trc("compiling signature pattern", redlog::field("input", pattern));
  log.dbg(
      "compiled signature", redlog::field("pattern", visual_pattern), redlog::field("bytes", result.pattern.size()),
      redlog::field("wildcards", wildcard_count)
  );

  return result;
}

compiled_patch compile_patch(const patch_pattern& pattern) {
  auto log = redlog::get_logger("p1ll.signature");

  compiled_patch result;

  if (!validate_patch_pattern(pattern)) {
    log.err("invalid patch pattern", redlog::field("pattern", pattern));
    return result;
  }

  std::string normalized = utils::normalize_hex_pattern(pattern);

  // reserve space for efficiency
  size_t byte_count = normalized.length() / 2;
  result.data.reserve(byte_count);
  result.mask.reserve(byte_count);

  for (size_t i = 0; i < normalized.length(); i += 2) {
    char first = normalized[i];
    char second = normalized[i + 1];

    if (first == '?' && second == '?') {
      // skip byte (don't patch)
      result.data.push_back(0x00);  // placeholder
      result.mask.push_back(false); // don't write
    } else {
      // patch byte
      char hex_byte[3] = {first, second, '\0'};
      uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
      result.data.push_back(byte);
      result.mask.push_back(true); // write this byte
    }
  }

  log.dbg(
      "compiled patch", redlog::field("pattern", pattern), redlog::field("bytes", result.data.size()),
      redlog::field("patches", std::count(result.mask.begin(), result.mask.end(), true))
  );

  return result;
}

bool validate_signature_pattern(const signature_pattern& pattern) { return utils::is_valid_hex_pattern(pattern); }

bool validate_patch_pattern(const patch_pattern& pattern) { return utils::is_valid_hex_pattern(pattern); }

signature_query create_signature_query(const signature_pattern& pattern, const signature_query_filter& filter) {
  signature_query query;
  query.signature = compile_signature(pattern);
  query.filter = filter;
  return query;
}

std::string patch_declaration::to_string() const {
  std::ostringstream oss;
  oss << "patch(" << signature.pattern << ", offset=" << offset << ", pattern=" << pattern
      << ", required=" << (required ? "true" : "false") << ")";
  return oss.str();
}

} // namespace p1ll::core