#include "module_discovery.hpp"
#include <algorithm>
#include <iostream>
#include <cstdio>
#include <redlog/redlog.hpp>

namespace w1 {
namespace util {

const module_info module_discovery::unknown_module_ = {"[unknown]", "[unknown]", 0, 0, module_type::UNKNOWN, false};

module_discovery::module_discovery() {}

void module_discovery::take_snapshot() {
  log_.vrb("taking module snapshot");
  std::unique_lock<std::shared_mutex> lock(mutex_);

  clear_internal_data();
  populate_from_qbdi_maps();
  log_.vrb("module snapshot complete");
}

const module_info& module_discovery::get_module_for_address(QBDI::rword address) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  auto it = address_map_.upper_bound(address);
  if (it != address_map_.begin()) {
    --it;
    const module_info& info = it->second;
    if (address >= info.base_address && address < info.base_address + info.size) {
      return info;
    }
  }

  return unknown_module_;
}

const module_info* module_discovery::find_module_by_name(const std::string& name) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  auto it = name_map_.find(name);
  return (it != name_map_.end()) ? it->second : nullptr;
}

std::vector<module_info> module_discovery::get_modules(std::function<bool(const module_info&)> filter) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);

  std::vector<module_info> result;

  for (const auto& pair : address_map_) {
    const module_info& info = pair.second;
    if (!filter || filter(info)) {
      result.push_back(info);
    }
  }

  return result;
}

std::vector<module_info> module_discovery::get_user_modules() const {
  return get_modules([](const module_info& info) { return !info.is_system_library; });
}

void module_discovery::clear_internal_data() {
  address_map_.clear();
  name_map_.clear();
}

void module_discovery::populate_from_qbdi_maps() {
  std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);
  log_.dbg("qbdi memory maps retrieved", redlog::field("total_maps", maps.size()));

  size_t exec_count = 0;
  for (const auto& map : maps) {
    if (map.permission & QBDI::PF_EXEC) {
      exec_count++;
      module_info info;
      info.path = map.name;
      info.base_address = map.range.start();
      info.size = map.range.end() - map.range.start();
      info.type = classify_module(map);
      info.is_system_library = is_system_library(map.name);

      // Generate meaningful name for unnamed modules
      if (map.name.empty()) {
        char unnamed_buf[32];
        snprintf(unnamed_buf, sizeof(unnamed_buf), "_unnamed_0x%08llx", (unsigned long long) info.base_address);
        info.name = unnamed_buf;
        info.path = info.name;
      } else {
        info.name = extract_basename(map.name);
      }

      log_.trc(
          "discovered executable module", redlog::field("name", info.name), redlog::field("path", info.path),
          redlog::field("base_address", "0x%08x", info.base_address), redlog::field("size", "0x%08x", info.size),
          redlog::field("type", static_cast<int>(info.type)), redlog::field("is_system", info.is_system_library)
      );

      address_map_[info.base_address] = info;
      name_map_[info.name] = &address_map_[info.base_address];
    }
  }

  log_.inf("module discovery complete", redlog::field("executable_modules", exec_count));
}

module_type module_discovery::classify_module(const QBDI::MemoryMap& map) const {
  if (map.name.empty()) {
    return module_type::ANONYMOUS_EXECUTABLE;
  }

  const std::string& name = map.name;

  // Check for shared libraries by extension
#ifdef __APPLE__
  if (name.find(".dylib") != std::string::npos) {
    return module_type::SHARED_LIBRARY;
  }
#elif defined(__linux__)
  if (name.find(".so") != std::string::npos) {
    return module_type::SHARED_LIBRARY;
  }
#elif defined(_WIN32)
  if (name.find(".dll") != std::string::npos) {
    return module_type::SHARED_LIBRARY;
  }
#endif

  // Everything else with a name is likely a main executable
  // (includes executables, kernel modules, etc.)
  return module_type::MAIN_EXECUTABLE;
}

bool module_discovery::is_system_library(const std::string& path) const {
  if (path.empty()) {
    return false;
  }

#ifdef __APPLE__
  return (path.find("/usr/lib/") == 0 || path.find("/System/Library/") == 0 || path.find("/Library/") == 0);
#elif defined(__linux__)
  return (
      path.find("/lib/") == 0 || path.find("/usr/lib/") == 0 || path.find("/lib64/") == 0 ||
      path.find("/usr/lib64/") == 0
  );
#elif defined(_WIN32)
  std::string lower_path = path;
  std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
  return (
      lower_path.find("c:\\windows\\") == 0 || lower_path.find("c:\\program files\\") == 0 ||
      lower_path.find("c:\\program files (x86)\\") == 0
  );
#else
  return false;
#endif
}

std::string module_discovery::extract_basename(const std::string& path) const {
  if (path.empty()) {
    return path;
  }

  size_t pos = path.find_last_of("/\\");
  if (pos != std::string::npos) {
    return path.substr(pos + 1);
  }

  return path;
}

} // namespace util
} // namespace w1