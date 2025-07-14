#pragma once

#include "types.hpp"
#include <string>
#include <vector>

namespace p1ll {

// forward declaration
class context;

// platform detector class - consolidates all platform detection logic
class platform_detector {
public:
  platform_detector() = default;

  // get detected platform information
  platform_key get_detected_platform() const;

  // get effective platform (respects context override if set)
  platform_key get_effective_platform(const context& ctx) const;

  // get platform hierarchy for matching
  std::vector<std::string> get_platform_hierarchy(const platform_key& platform) const;
  std::vector<std::string> get_platform_hierarchy_for_context(const context& ctx) const;

  // platform validation
  bool is_valid_platform_key(const platform_key& platform) const;
  bool platform_matches(const platform_key& key, const platform_key& target) const;

  // get supported platforms/architectures
  std::vector<std::string> get_supported_operating_systems() const;
  std::vector<std::string> get_supported_architectures() const;

  // parse platform key from string like "linux:x64" or "darwin:*"
  platform_key parse_platform_key(const std::string& platform_str) const;

private:
  // platform detection implementation
  std::string detect_operating_system() const;
  std::string detect_architecture() const;
};

// global platform detector instance
platform_detector& get_platform_detector();

} // namespace p1ll