#pragma once

#include "result.hpp"
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace p1ll::engine {

// parsed pattern with mask; mask byte 1 means match/write, 0 means wildcard/skip
struct pattern {
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;

  size_t size() const noexcept { return bytes.size(); }
  bool empty() const noexcept { return bytes.empty(); }
};

result<pattern> parse_signature(std::string_view hex);
result<pattern> parse_patch(std::string_view hex);

} // namespace p1ll::engine
