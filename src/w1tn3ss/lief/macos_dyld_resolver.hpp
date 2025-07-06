#pragma once

#ifdef __APPLE__

#include <string>
#include <optional>
#include <redlog.hpp>

namespace w1::lief {

// resolves system library paths to extracted dyld shared cache dump paths
class macos_dyld_resolver {
public:
  macos_dyld_resolver();

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

  // check if path is a system library that would be in dyld cache
  bool is_dyld_cached_library(const std::string& path) const;

  // helper to search for library in dump
  std::optional<std::string> find_library_in_dump(const std::string& library_name) const;

  // extract library name from full path
  std::string extract_library_name(const std::string& path) const;

  // normalize path for consistent matching
  std::string normalize_path(const std::string& path) const;
};

} // namespace w1::lief

#endif // __APPLE__