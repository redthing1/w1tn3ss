#ifdef _WIN32

#include "windows_path_resolver.hpp"
#include <windows.h>
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace w1::symbols {

namespace fs = std::filesystem;

windows_path_resolver::windows_path_resolver() : log_("w1.windows_path_resolver") {
  log_.dbg("initializing windows path resolver");

  system_directories_ = discover_system_directories();

  if (system_directories_.empty()) {
    log_.err("failed to discover any windows system directories");
  } else {
    log_.trc("windows path resolver initialized", redlog::field("system_directories", system_directories_.size()));

    for (const auto& dir : system_directories_) {
      log_.dbg("system directory", redlog::field("path", dir));
    }
  }
}

std::optional<std::string> windows_path_resolver::resolve_library_path(const std::string& library_name) const {
  if (library_name.empty()) {
    return std::nullopt;
  }

  // normalize basename for consistent caching
  std::string norm_basename = normalize_basename(library_name);

  log_.trc(
      "attempting to resolve library path", redlog::field("library", library_name),
      redlog::field("normalized", norm_basename)
  );

  // check cache first
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = path_cache_.find(norm_basename);
    if (it != path_cache_.end()) {
      log_.dbg(
          "path resolver cache hit", redlog::field("library", norm_basename), redlog::field("cached_path", it->second),
          redlog::field("cache_size", path_cache_.size())
      );
      return it->second;
    }
    log_.dbg(
        "path resolver cache miss", redlog::field("library", norm_basename),
        redlog::field("cache_size", path_cache_.size())
    );
  }

  // if it's already a full path and exists, return it
  if (library_name.find('\\') != std::string::npos || library_name.find('/') != std::string::npos) {
    try {
      if (fs::exists(library_name) && fs::is_regular_file(library_name)) {
        // cache the result
        std::lock_guard<std::mutex> lock(cache_mutex_);
        path_cache_[norm_basename] = library_name;
        return library_name;
      }
    } catch (const fs::filesystem_error& e) {
      log_.warn(
          "filesystem error checking path", redlog::field("path", library_name), redlog::field("error", e.what())
      );
    }
  }

  // search in system directories
  auto resolved_path = find_in_system_directories(norm_basename);

  if (resolved_path) {
    log_.dbg(
        "resolved library path", redlog::field("library", library_name), redlog::field("resolved_path", *resolved_path)
    );

    // cache the result
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      path_cache_[norm_basename] = *resolved_path;
    }

    return resolved_path;
  }

  log_.trc("library not found", redlog::field("library", library_name));
  return std::nullopt;
}

bool windows_path_resolver::is_system_library(const std::string& path) const {
  std::string basename = path;
  size_t last_slash = basename.find_last_of("\\/");
  if (last_slash != std::string::npos) {
    basename = basename.substr(last_slash + 1);
  }

  return is_likely_system_library(basename);
}

std::vector<std::string> windows_path_resolver::discover_system_directories() const {
  std::vector<std::string> directories;

  log_.dbg("discovering windows system directories");

  // get system32 directory
  wchar_t system32_path[MAX_PATH];
  UINT system32_len = GetSystemDirectoryW(system32_path, MAX_PATH);
  if (system32_len > 0 && system32_len < MAX_PATH) {
    // convert wide string to narrow string
    char narrow_path[MAX_PATH];
    int converted = WideCharToMultiByte(CP_UTF8, 0, system32_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);
    if (converted > 0) {
      std::string system32_str(narrow_path);
      directories.push_back(system32_str);
      log_.dbg("found system32 directory", redlog::field("path", system32_str));
    }
  }

  // get windows directory
  wchar_t windows_path[MAX_PATH];
  UINT windows_len = GetWindowsDirectoryW(windows_path, MAX_PATH);
  if (windows_len > 0 && windows_len < MAX_PATH) {
    char narrow_path[MAX_PATH];
    int converted = WideCharToMultiByte(CP_UTF8, 0, windows_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);
    if (converted > 0) {
      std::string windows_str(narrow_path);
      directories.push_back(windows_str);
      log_.dbg("found windows directory", redlog::field("path", windows_str));
    }
  }

  // add syswow64 directory (for 32-bit dlls on 64-bit systems)
  if (!directories.empty()) {
    // construct syswow64 path from windows directory
    wchar_t syswow64_path[MAX_PATH];
    if (windows_len > 0) {
      // replace "System32" with "SysWOW64" in windows path, or append it
      std::wstring windows_wide(windows_path);
      std::wstring syswow64_wide = windows_wide + L"\\SysWOW64";

      if (syswow64_wide.length() < MAX_PATH) {
        wcscpy_s(syswow64_path, MAX_PATH, syswow64_wide.c_str());

        char narrow_path[MAX_PATH];
        int converted = WideCharToMultiByte(CP_UTF8, 0, syswow64_path, -1, narrow_path, MAX_PATH, nullptr, nullptr);
        if (converted > 0) {
          std::string syswow64_str(narrow_path);
          // check if directory exists before adding
          if (fs::exists(syswow64_str) && fs::is_directory(syswow64_str)) {
            directories.push_back(syswow64_str);
            log_.dbg("found syswow64 directory", redlog::field("path", syswow64_str));
          }
        }
      }
    }
  }

  log_.trc("system directory discovery complete", redlog::field("directories_found", directories.size()));

  return directories;
}

std::optional<std::string> windows_path_resolver::find_in_system_directories(const std::string& basename) const {
  log_.trc(
      "searching for library in system directories", redlog::field("basename", basename),
      redlog::field("directories_to_search", system_directories_.size())
  );

  for (const auto& dir : system_directories_) {
    std::string full_path = dir + "\\" + basename;

    log_.trc("checking path", redlog::field("full_path", full_path));

    try {
      if (fs::exists(full_path) && fs::is_regular_file(full_path)) {
        log_.dbg("found library file", redlog::field("basename", basename), redlog::field("full_path", full_path));
        return full_path;
      }
    } catch (const fs::filesystem_error& e) {
      log_.warn(
          "filesystem error while checking path", redlog::field("path", full_path), redlog::field("error", e.what())
      );
      continue;
    }
  }

  log_.trc("library not found in any system directory", redlog::field("basename", basename));
  return std::nullopt;
}

std::string windows_path_resolver::normalize_basename(const std::string& basename) const {
  std::string normalized = basename;

  // convert to lowercase for case-insensitive matching
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](char c) { return std::tolower(c); });

  return normalized;
}

bool windows_path_resolver::is_likely_system_library(const std::string& basename) const {
  if (basename.empty()) {
    return false;
  }

  // must be a dll
  if (basename.find(".dll") == std::string::npos) {
    return false;
  }

  // common windows system library patterns
  static const std::vector<std::string> system_patterns = {
      "kernel32.dll", "ntdll.dll", "user32.dll",   "gdi32.dll",      "advapi32.dll", "shell32.dll",
      "shlwapi.dll",  "ole32.dll", "oleaut32.dll", "rpcrt4.dll",     "ucrtbase.dll", "msvcrt.dll",
      "msvcp",        "vcruntime", "api-ms-win-",  "kernelbase.dll", "sechost.dll",  "comctl32.dll",
      "ws2_32.dll",   "winmm.dll", "version.dll",  "imm32.dll",      "setupapi.dll"
  };

  std::string lower_basename = normalize_basename(basename);

  for (const auto& pattern : system_patterns) {
    if (lower_basename.find(pattern) == 0 || lower_basename == pattern) {
      log_.trc(
          "matched system library pattern", redlog::field("basename", basename), redlog::field("pattern", pattern)
      );
      return true;
    }
  }

  log_.trc("no system library pattern match", redlog::field("basename", basename));
  return false;
}

} // namespace w1::symbols

#endif // _WIN32