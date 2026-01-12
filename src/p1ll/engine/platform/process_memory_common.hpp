#pragma once

#include "engine/types.hpp"
#include <algorithm>
#include <cctype>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace p1ll::engine::platform {

// best-effort system library detection based on path prefixes
inline bool is_system_region(const memory_region& region) {
  if (region.name.empty()) {
    return false;
  }
#ifdef _WIN32
  char system_path_buf[MAX_PATH];
  if (GetSystemDirectoryA(system_path_buf, MAX_PATH) == 0) {
    return false;
  }
  std::string system_path(system_path_buf);
  std::string module_path = region.name;
  std::transform(system_path.begin(), system_path.end(), system_path.begin(), ::tolower);
  std::transform(module_path.begin(), module_path.end(), module_path.begin(), ::tolower);
  return module_path.rfind(system_path, 0) == 0;
#elif defined(__APPLE__)
  return region.name.rfind("/System/", 0) == 0 || region.name.rfind("/usr/lib/", 0) == 0 ||
         region.name.rfind("/usr/libexec/", 0) == 0;
#elif defined(__linux__)
  return region.name.rfind("/lib/", 0) == 0 || region.name.rfind("/usr/lib/", 0) == 0 ||
         region.name.rfind("/lib64/", 0) == 0 || region.name.rfind("/usr/lib64/", 0) == 0 ||
         region.name.rfind("/usr/libexec/", 0) == 0;
#else
  return false;
#endif
}

} // namespace p1ll::engine::platform
