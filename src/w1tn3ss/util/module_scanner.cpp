#include "module_scanner.hpp"
#include <algorithm>
#include <cstdio>

namespace w1 {
namespace util {

module_scanner::module_scanner() {}

std::vector<module_info> module_scanner::scan_executable_modules() {
  log_.vrb("scanning executable modules");

  std::vector<module_info> modules;

  try {
    auto maps = get_executable_maps();
    modules.reserve(maps.size());

    for (const auto& map : maps) {
      modules.push_back(build_module_info(map));
    }

    log_.inf("module scan complete", redlog::field("executable_modules", modules.size()));
  } catch (const std::exception& e) {
    log_.err("failed to scan executable modules", redlog::field("error", e.what()));
    return {};
  }

  return modules;
}

std::vector<module_info> module_scanner::scan_user_modules() const {
  // we need to bypass the const issue here - scan is read-only but log_ is mutable
  auto& mutable_log = const_cast<redlog::logger&>(log_);
  auto& mutable_scanner = const_cast<module_scanner&>(*this);

  auto all_modules = mutable_scanner.scan_executable_modules();

  std::vector<module_info> user_modules;
  user_modules.reserve(all_modules.size() / 2); // estimate

  std::copy_if(all_modules.begin(), all_modules.end(), std::back_inserter(user_modules), [](const module_info& mod) {
    return !mod.is_system_library;
  });

  mutable_log.dbg(
      "user module filter applied", redlog::field("total_modules", all_modules.size()),
      redlog::field("user_modules", user_modules.size())
  );

  return user_modules;
}

std::vector<module_info> module_scanner::scan_new_modules(const std::unordered_set<QBDI::rword>& known_bases) {
  log_.vrb("scanning for new modules", redlog::field("known_modules", known_bases.size()));

  auto all_modules = scan_executable_modules();

  std::vector<module_info> new_modules;
  new_modules.reserve(all_modules.size() / 4); // estimate fewer new modules

  std::copy_if(
      all_modules.begin(), all_modules.end(), std::back_inserter(new_modules),
      [&known_bases](const module_info& mod) { return known_bases.find(mod.base_address) == known_bases.end(); }
  );

  log_.dbg(
      "new module scan complete", redlog::field("total_modules", all_modules.size()),
      redlog::field("new_modules", new_modules.size())
  );

  return new_modules;
}

std::vector<QBDI::MemoryMap> module_scanner::get_executable_maps() {
  auto all_maps = QBDI::getCurrentProcessMaps(false);

  std::vector<QBDI::MemoryMap> exec_maps;
  exec_maps.reserve(all_maps.size() / 4); // estimate executable fraction

  std::copy_if(all_maps.begin(), all_maps.end(), std::back_inserter(exec_maps), [](const QBDI::MemoryMap& map) {
    return map.permission & QBDI::PF_EXEC;
  });

  log_.trc(
      "filtered executable maps", redlog::field("total_maps", all_maps.size()),
      redlog::field("executable_maps", exec_maps.size())
  );

  return exec_maps;
}

module_info module_scanner::build_module_info(const QBDI::MemoryMap& map) {
  module_info info;
  info.path = map.name;
  info.base_address = map.range.start();
  info.size = map.range.end() - map.range.start();
  info.type = classify_module(map);
  info.is_system_library = is_system_library(map.name);

  // generate meaningful name for unnamed modules
  if (map.name.empty()) {
    char unnamed_buf[32];
    snprintf(unnamed_buf, sizeof(unnamed_buf), "_unnamed_0x%08llx", static_cast<unsigned long long>(info.base_address));
    info.name = unnamed_buf;
    info.path = info.name;
  } else {
    info.name = extract_basename(map.name);
  }

  log_.dbg(
      "built module info", redlog::field("name", info.name), redlog::field("path", info.path),
      redlog::field("base_address", "0x%08x", info.base_address), redlog::field("size", "0x%08x", info.size),
      redlog::field("type", static_cast<int>(info.type)), redlog::field("is_system", info.is_system_library)
  );

  return info;
}

module_type module_scanner::classify_module(const QBDI::MemoryMap& map) const {
  if (map.name.empty()) {
    return module_type::ANONYMOUS_EXECUTABLE;
  }

  const std::string& name = map.name;

  // check for shared libraries by extension
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

  // everything else with a name is likely a main executable
  return module_type::MAIN_EXECUTABLE;
}

bool module_scanner::is_system_library(const std::string& path) const {
  if (path.empty()) {
    return false;
  }

#ifdef __APPLE__
  // check for full paths
  if (path.find("/usr/lib/") == 0 || path.find("/System/Library/") == 0 || path.find("/Library/") == 0) {
    return true;
  }
  // check for system library names (when loaded from dyld shared cache)
  if (path.find("libsystem") == 0 || path.find("libc++") == 0 || path.find("libobjc") == 0 ||
      path.find("libdispatch") == 0 || path.find("libxpc") == 0 || path.find("libcorecrypto") == 0 ||
      path.find("libcompiler_rt") == 0 || path.find("libdyld") == 0 || path.find("dyld") == 0 ||
      path.find("libquarantine") == 0 || path.find("libmacho") == 0 || path.find("libcommonCrypto") == 0 ||
      path.find("libunwind") == 0 || path.find("libcopyfile") == 0 || path.find("libremovefile") == 0 ||
      path.find("libkeymgr") == 0 || path.find("libcache") == 0 || path.find("libSystem") == 0) {
    return true;
  }
  return false;
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

std::string module_scanner::extract_basename(const std::string& path) const {
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