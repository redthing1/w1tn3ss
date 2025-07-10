#pragma once

#ifdef __APPLE__

#include "path_resolver.hpp"
#include <string>
#include <optional>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <redlog.hpp>

namespace w1::symbols {

// resolves system library paths to extracted dyld shared cache dump paths
class macos_dyld_resolver : public path_resolver {
public:
  macos_dyld_resolver();

  // path_resolver interface
  std::optional<std::string> resolve_library_path(const std::string& library_name) const override;
  std::vector<std::string> get_system_directories() const override;
  bool is_system_library(const std::string& path) const override;
  std::string get_name() const override { return "macos_dyld"; }

  // resolve system library path to extracted dyld dump path
  // returns empty optional if resolution fails or not applicable
  std::optional<std::string> resolve_extracted_path(const std::string& original_path) const;

  // check if dyld dump is available
  bool is_available() const { return !dump_dir_.empty(); }

  // get the configured dump directory
  const std::string& get_dump_dir() const { return dump_dir_; }

private:
  std::string dump_dir_;
  mutable redlog::logger log_;

  // Pre-computed cache of library name to dump path mappings
  mutable std::unordered_map<std::string, std::string> library_cache_;
  mutable std::mutex cache_mutex_;

  // check if path is a system library that would be in dyld cache
  bool is_dyld_cached_library(const std::string& path) const;

  // helper to search for library in dump
  std::optional<std::string> find_library_in_dump(const std::string& library_name) const;

  // extract library name from full path
  std::string extract_library_name(const std::string& path) const;

  // normalize path for consistent matching
  std::string normalize_path(const std::string& path) const;

  // pre-populate library cache
  void populate_library_cache();
};

} // namespace w1::symbols

#endif // __APPLE__