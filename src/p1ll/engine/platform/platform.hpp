#pragma once

#include "engine/result.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace p1ll::engine::platform {

struct platform_key {
  std::string os;
  std::string arch;

  std::string to_string() const { return os + ":" + arch; }
};

platform_key detect_platform();
result<platform_key> parse_platform(std::string_view key);
bool platform_matches(const platform_key& selector, const platform_key& target);
bool platform_matches(std::string_view selector, const platform_key& target);
bool any_platform_matches(const std::vector<std::string>& selectors, const platform_key& target);

} // namespace p1ll::engine::platform
