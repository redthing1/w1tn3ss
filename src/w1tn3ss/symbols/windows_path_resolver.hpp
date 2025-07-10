#pragma once

#ifdef _WIN32

#include "path_resolver.hpp"
#include <redlog.hpp>
#include <mutex>
#include <unordered_map>

namespace w1::symbols {

/**
 * @brief windows path resolver for system libraries
 *
 * resolves system library names to full paths using windows APIs
 * and knowledge of system directories.
 */
class windows_path_resolver : public path_resolver {
public:
  windows_path_resolver();
  ~windows_path_resolver() = default;

  // path_resolver interface
  std::optional<std::string> resolve_library_path(const std::string& library_name) const override;
  std::vector<std::string> get_system_directories() const override { return system_directories_; }
  bool is_system_library(const std::string& path) const override;
  std::string get_name() const override { return "windows_path"; }

private:
  // helper methods
  std::vector<std::string> discover_system_directories() const;
  std::optional<std::string> find_in_system_directories(const std::string& basename) const;
  std::string normalize_basename(const std::string& basename) const;
  bool is_likely_system_library(const std::string& basename) const;

  // system directories
  std::vector<std::string> system_directories_;

  // path cache
  mutable std::mutex cache_mutex_;
  mutable std::unordered_map<std::string, std::string> path_cache_;

  // logging
  redlog::logger log_;
};

} // namespace w1::symbols

#endif // _WIN32