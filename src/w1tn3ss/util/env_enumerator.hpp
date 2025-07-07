#pragma once

#include <string>
#include <unordered_map>

#ifdef _WIN32
#include <common/windows_clean.hpp>
#endif

namespace w1::util {

/**
 * @brief Portable environment variable enumeration
 *
 * This utility provides a clean, cross-platform way to enumerate
 * environment variables that match a given prefix.
 */
class env_enumerator {
public:
  /**
   * @brief Get all environment variables with the specified prefix
   * @param prefix The prefix to match (e.g., "W1SCRIPT_")
   * @return Map of environment variable names (without prefix) to values
   */
  static std::unordered_map<std::string, std::string> get_vars_with_prefix(const std::string& prefix);
};

} // namespace w1::util