#pragma once

#include "types.hpp"
#include <string>
#include <vector>

namespace p1ll::core {

// get current platform information
platform_key get_current_platform();

// parse platform key from string like "linux:x64" or "darwin:*"
platform_key parse_platform_key(const std::string& platform_str);

// get platform hierarchy for matching: "linux:x64" -> ["linux:x64", "linux:*", "*:*"]
std::vector<std::string> get_platform_hierarchy(const platform_key& platform);

// get platform hierarchy for current platform
std::vector<std::string> get_current_platform_hierarchy();

// check if platform key matches another (with wildcard support)
bool platform_matches(const platform_key& key, const platform_key& target);

// validate platform key components are reasonable
bool is_valid_platform_key(const platform_key& platform);

// get list of known/supported operating systems
std::vector<std::string> get_supported_operating_systems();

// get list of known/supported architectures
std::vector<std::string> get_supported_architectures();

} // namespace p1ll::core