#ifdef __APPLE__

#include "macos_dyld_resolver.hpp"
#include <cstdlib>
#include <filesystem>
#include <algorithm>

namespace w1::lief {

namespace fs = std::filesystem;

macos_dyld_resolver::macos_dyld_resolver() : log_("w1.macos_dyld_resolver") {

  // check for dyld shared cache dump directory
  const char* dump_dir_env = std::getenv("DYLD_SHARED_CACHE_DUMP_DIR");

  if (dump_dir_env && *dump_dir_env) {
    dump_dir_ = dump_dir_env;

    // normalize path - remove trailing slash
    if (!dump_dir_.empty() && dump_dir_.back() == '/') {
      dump_dir_.pop_back();
    }

    // verify directory exists
    if (fs::exists(dump_dir_) && fs::is_directory(dump_dir_)) {
      log_.trc("dyld shared cache dump directory configured", redlog::field("path", dump_dir_));
      // Pre-populate the library cache
      populate_library_cache();
    } else {
      log_.warn("dyld shared cache dump directory not found", redlog::field("path", dump_dir_));
      dump_dir_.clear();
    }
  } else {
    log_.dbg("DYLD_SHARED_CACHE_DUMP_DIR not set");
  }
}

std::optional<std::string> macos_dyld_resolver::resolve_extracted_path(const std::string& original_path) const {

  if (!is_available()) {
    return std::nullopt;
  }

  log_.trc("attempting to resolve dyld cached library", redlog::field("original_path", original_path));

  // check if this is a system library that would be in dyld cache
  if (!is_dyld_cached_library(original_path)) {
    log_.trc("not a dyld cached library", redlog::field("path", original_path));
    return std::nullopt;
  }

  // Extract library name and check pre-computed cache first
  std::string library_name = extract_library_name(original_path);
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = library_cache_.find(library_name);
    if (it != library_cache_.end()) {
      log_.trc(
          "found library in pre-computed cache", redlog::field("original", original_path),
          redlog::field("resolved", it->second)
      );
      return it->second;
    }
  }

  // strategy 1: direct path mapping
  // /usr/lib/system/libsystem_c.dylib -> $DUMP_DIR/usr/lib/system/libsystem_c.dylib
  std::string direct_path = dump_dir_ + original_path;

  log_.trc("trying direct path mapping", redlog::field("mapped_path", direct_path));

  if (fs::exists(direct_path)) {
    log_.trc(
        "found library in dyld dump (direct mapping)", redlog::field("original", original_path),
        redlog::field("resolved", direct_path)
    );
    return direct_path;
  }

  // strategy 2: search for library name in dump
  log_.trc("direct mapping failed, searching for library", redlog::field("library_name", library_name));

  if (auto found_path = find_library_in_dump(library_name)) {
    log_.trc(
        "found library in dyld dump (recursive search)", redlog::field("original", original_path),
        redlog::field("resolved", *found_path), redlog::field("library_name", library_name)
    );
    // Cache the result
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      library_cache_[library_name] = *found_path;
    }
    return found_path;
  }

  log_.trc(
      "library not found in dyld dump", redlog::field("original_path", original_path),
      redlog::field("library_name", library_name)
  );

  return std::nullopt;
}

bool macos_dyld_resolver::is_dyld_cached_library(const std::string& path) const {
  log_.trc("checking if path is dyld cached library", redlog::field("path", path));

  // common system library paths that are in dyld shared cache
  static const std::vector<std::string> cached_prefixes = {
      "/usr/lib/", "/System/Library/Frameworks/", "/System/Library/PrivateFrameworks/", "/System/iOSSupport/",
      "/Library/Apple/"
  };

  // also check common library names without full paths
  static const std::vector<std::string> cached_lib_patterns = {"libsystem_",  "libc++",         "libobjc",
                                                               "libdispatch", "libdyld",        "libxpc",
                                                               "Foundation",  "CoreFoundation", "CoreServices"};

  // normalize the path
  std::string norm_path = normalize_path(path);

  // extract just the filename if it's a full path
  std::string filename = extract_library_name(path);

  log_.trc(
      "normalized path and extracted filename", redlog::field("norm_path", norm_path),
      redlog::field("filename", filename)
  );

  // check if path starts with any cached prefix
  for (const auto& prefix : cached_prefixes) {
    if (norm_path.find(prefix) == 0) {
      log_.trc("matched cached prefix", redlog::field("prefix", prefix), redlog::field("path", path));
      return true;
    }
  }

  // check if filename matches common cached library patterns
  for (const auto& pattern : cached_lib_patterns) {
    if (filename.find(pattern) == 0) {
      log_.trc(
          "matched cached library pattern", redlog::field("pattern", pattern), redlog::field("filename", filename)
      );
      return true;
    }
  }

  log_.trc("not a dyld cached library", redlog::field("path", path));
  return false;
}

std::optional<std::string> macos_dyld_resolver::find_library_in_dump(const std::string& library_name) const {

  log_.trc(
      "searching for library in dump", redlog::field("library_name", library_name), redlog::field("dump_dir", dump_dir_)
  );

  if (library_name.empty()) {
    log_.trc("library name is empty, returning nullopt");
    return std::nullopt;
  }

  try {
    // common subdirectories where libraries are typically found
    static const std::vector<std::string> search_subdirs = {
        "/usr/lib", "/usr/lib/system", "/System/Library/Frameworks", "/System/Library/PrivateFrameworks"
    };

    // first search in common locations
    for (const auto& subdir : search_subdirs) {
      std::string search_path = dump_dir_ + subdir;

      if (!fs::exists(search_path)) {
        log_.trc("search path does not exist", redlog::field("search_path", search_path));
        continue;
      }

      log_.trc("searching in directory", redlog::field("path", search_path), redlog::field("library", library_name));

      // look for exact match and versioned variants
      for (const auto& entry : fs::directory_iterator(search_path)) {
        if (!entry.is_regular_file() && !entry.is_symlink()) {
          continue;
        }

        std::string filename = entry.path().filename().string();

        // exact match
        if (filename == library_name) {
          log_.trc(
              "found exact library match", redlog::field("library", library_name),
              redlog::field("path", entry.path().string())
          );
          return entry.path().string();
        }

        // handle versioned libraries (e.g., libsystem_c.dylib vs libsystem_c.1.dylib)
        std::string base_name = library_name;
        size_t dot_pos = base_name.rfind(".dylib");
        if (dot_pos != std::string::npos) {
          base_name = base_name.substr(0, dot_pos);

          // check if filename starts with base_name and ends with .dylib
          if (filename.find(base_name) == 0 && filename.rfind(".dylib") == filename.length() - 6) {

            log_.trc(
                "found versioned match", redlog::field("requested", library_name), redlog::field("found", filename)
            );
            return entry.path().string();
          }
        }
      }
    }

    // if not found in common locations, do recursive search as last resort
    log_.trc("library not found in common locations, trying recursive search", redlog::field("library", library_name));

    // limit recursion depth to avoid excessive searching
    constexpr int max_depth = 5;

    std::function<std::optional<std::string>(const fs::path&, int)> search_recursive;
    search_recursive = [&](const fs::path& dir, int depth) -> std::optional<std::string> {
      if (depth > max_depth) {
        return std::nullopt;
      }

      for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_directory()) {
          if (auto result = search_recursive(entry.path(), depth + 1)) {
            return result;
          }
        } else if (entry.is_regular_file() || entry.is_symlink()) {
          std::string filename = entry.path().filename().string();
          if (filename == library_name) {
            return entry.path().string();
          }
        }
      }

      return std::nullopt;
    };

    return search_recursive(dump_dir_, 0);

  } catch (const fs::filesystem_error& e) {
    log_.err(
        "filesystem error while searching for library", redlog::field("library", library_name),
        redlog::field("error", e.what())
    );
    return std::nullopt;
  } catch (const std::exception& e) {
    log_.err(
        "unexpected error while searching for library", redlog::field("library", library_name),
        redlog::field("error", e.what())
    );
    return std::nullopt;
  }
}

std::string macos_dyld_resolver::extract_library_name(const std::string& path) const {
  // extract just the filename from the path
  size_t last_slash = path.rfind('/');
  if (last_slash != std::string::npos) {
    return path.substr(last_slash + 1);
  }
  return path;
}

std::string macos_dyld_resolver::normalize_path(const std::string& path) const {
  // remove any redundant slashes and resolve symlinks if needed
  try {
    // for now, just ensure single slashes
    std::string result;
    result.reserve(path.size());

    bool last_was_slash = false;
    for (char c : path) {
      if (c == '/') {
        if (!last_was_slash) {
          result += c;
        }
        last_was_slash = true;
      } else {
        result += c;
        last_was_slash = false;
      }
    }

    return result;
  } catch (...) {
    return path;
  }
}

void macos_dyld_resolver::populate_library_cache() {
  log_.trc("pre-populating dyld library cache", redlog::field("dump_dir", dump_dir_));

  std::lock_guard<std::mutex> lock(cache_mutex_);
  library_cache_.clear();

  // Common subdirectories where libraries are typically found
  static const std::vector<std::string> search_subdirs = {
      "/usr/lib", "/usr/lib/system", "/System/Library/Frameworks", "/System/Library/PrivateFrameworks"
  };

  size_t total_libraries = 0;

  try {
    for (const auto& subdir : search_subdirs) {
      std::string search_path = dump_dir_ + subdir;

      if (!fs::exists(search_path)) {
        continue;
      }

      for (const auto& entry : fs::directory_iterator(search_path)) {
        if (!entry.is_regular_file() && !entry.is_symlink()) {
          continue;
        }

        std::string filename = entry.path().filename().string();
        if (filename.find(".dylib") != std::string::npos || filename.find(".framework") != std::string::npos) {
          library_cache_[filename] = entry.path().string();
          total_libraries++;
        }
      }
    }
  } catch (const fs::filesystem_error& e) {
    log_.err("filesystem error while populating cache", redlog::field("error", e.what()));
  }

  log_.trc("dyld library cache populated", redlog::field("total_libraries", total_libraries));
}

} // namespace w1::lief

#endif // __APPLE__