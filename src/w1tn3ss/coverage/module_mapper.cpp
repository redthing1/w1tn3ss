#include "module_mapper.hpp"
#include "common/platform_utils.hpp"
#include "coverage_data.hpp"
#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>
#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <cstring>

// qbdi includes
#include <QBDI.h>

namespace w1::coverage {

module_mapper::module_mapper(coverage_collector& collector)
    : log_(redlog::get_logger("w1tn3ss.module_mapper")), collector_(collector), exclude_system_(true) {
  log_.debug("module mapper initialized");
}

module_mapper::~module_mapper() {
  log_.debug("module mapper destroyed", redlog::field("total_regions", regions_.size()));
}

bool module_mapper::discover_process_modules() {
  log_.info(
      "discovering process modules", redlog::field("exclude_system", exclude_system_),
      redlog::field("patterns", target_patterns_.size())
  );

  // clear existing regions
  regions_.clear();

  bool success = false;

#ifdef __APPLE__
  log_.debug("using darwin platform module discovery");
  success = discover_modules_darwin();
#elif defined(__linux__)
  log_.debug("using linux platform module discovery");
  success = discover_modules_linux();
#else
  log_.debug("using generic unix platform module discovery");
  success = discover_modules_unix();
#endif

  if (success) {
    size_t executable_count = get_executable_count();
    size_t user_count = get_user_module_count();

    log_.info(
        "module discovery completed", redlog::field("regions", regions_.size()),
        redlog::field("executable", executable_count), redlog::field("user", user_count),
        redlog::field("system", executable_count - user_count)
    );

    // log memory layout summary
    if (!regions_.empty()) {
      uint64_t min_addr = UINT64_MAX, max_addr = 0;
      for (const auto& region : regions_) {
        if (region.is_executable) {
          min_addr = std::min(min_addr, region.start);
          max_addr = std::max(max_addr, region.end);
        }
      }

      if (min_addr != UINT64_MAX) {
        log_.verbose(
            "executable memory layout", redlog::field("min_addr", min_addr), redlog::field("max_addr", max_addr),
            redlog::field("space_size", max_addr - min_addr)
        );
      }
    }

  } else {
    log_.error(
        "module discovery failed - no memory regions discovered", redlog::field(
                                                                      "platform",
#ifdef __APPLE__
                                                                      "darwin"
#elif defined(__linux__)
                                                                      "linux"
#else
                                                                      "generic_unix"
#endif
                                                                  )
    );

    // provide diagnostic information
    log_.debug(
        "diagnostic information", redlog::field("pid", getpid()), redlog::field("uid", getuid()),
        redlog::field("euid", geteuid())
    );
  }

  return success;
}

bool module_mapper::discover_qbdi_modules() {
  log_.info("discovering modules via qbdi");

  try {
    // use qbdi to get current process memory maps
    log_.debug("calling QBDI::getCurrentProcessMaps()");
    std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps();

    if (maps.empty()) {
      log_.error("qbdi returned empty memory map list");
      return false;
    }

    log_.debug("qbdi returned memory maps", redlog::field("count", maps.size()));

    // log summary of map types for debugging
    size_t executable_maps = 0, readable_maps = 0, writable_maps = 0;
    size_t named_maps = 0, anonymous_maps = 0;

    for (const auto& map : maps) {
      if (map.permission & QBDI::PF_EXEC) {
        executable_maps++;
      }
      if (map.permission & QBDI::PF_READ) {
        readable_maps++;
      }
      if (map.permission & QBDI::PF_WRITE) {
        writable_maps++;
      }

      if (!map.name.empty()) {
        named_maps++;
      } else {
        anonymous_maps++;
      }
    }

    log_.verbose(
        "qbdi memory map summary", redlog::field("total", maps.size()), redlog::field("executable", executable_maps),
        redlog::field("readable", readable_maps), redlog::field("writable", writable_maps),
        redlog::field("named", named_maps), redlog::field("anonymous", anonymous_maps)
    );

    return convert_qbdi_memory_maps(maps);

  } catch (const std::exception& e) {
    log_.error(
        "qbdi module discovery failed", redlog::field("error", e.what()),
        redlog::field("exception_type", typeid(e).name())
    );

    // provide fallback diagnostic information
    log_.debug("attempting fallback memory layout detection");

    return false;
  }
}

size_t module_mapper::register_discovered_modules() {
  log_.info(
      "registering discovered modules with coverage collector", redlog::field("regions", regions_.size()),
      redlog::field("exclude_system", exclude_system_)
  );

  size_t registered_count = 0;
  size_t excluded_count = 0;
  size_t non_executable_count = 0;
  size_t pattern_filtered_count = 0;

  for (const auto& region : regions_) {
    if (!region.is_executable) {
      non_executable_count++;
      continue;
    }

    if (exclude_system_ && is_system_module(region.name)) {
      excluded_count++;
      log_.trace(
          "excluding system module", redlog::field("name", region.name), redlog::field("start", region.start),
          redlog::field("size", region.size())
      );
      continue;
    }

    if (!matches_target_pattern(region.name)) {
      pattern_filtered_count++;
      log_.trace(
          "module filtered by target patterns", redlog::field("name", region.name),
          redlog::field("patterns", target_patterns_.size())
      );
      continue;
    }

    uint16_t module_id = collector_.add_module(region.name, region.start, region.end);

    if (module_id != UINT16_MAX) {
      registered_count++;
      log_.verbose(
          "module registered", redlog::field("id", module_id), redlog::field("name", region.name),
          redlog::field("start", region.start), redlog::field("end", region.end), redlog::field("size", region.size()),
          redlog::field("permissions", region.permission)
      );
    } else {
      log_.warn(
          "failed to register module", redlog::field("name", region.name), redlog::field("start", region.start),
          redlog::field("size", region.size())
      );
    }
  }

  log_.info(
      "module registration completed", redlog::field("registered", registered_count),
      redlog::field("total", regions_.size()), redlog::field("excluded", excluded_count),
      redlog::field("not_exec", non_executable_count), redlog::field("filtered", pattern_filtered_count)
  );

  if (registered_count == 0 && regions_.size() > 0) {
    log_.warn(
        "no modules were registered despite having memory regions", redlog::field("executable", get_executable_count()),
        redlog::field("user", get_user_module_count())
    );
  }

  return registered_count;
}

const memory_region* module_mapper::find_region_by_address(uint64_t address) const {
  for (const auto& region : regions_) {
    if (region.contains(address)) {
      return &region;
    }
  }
  return nullptr;
}

std::vector<memory_region> module_mapper::get_executable_regions() const {
  std::vector<memory_region> executable_regions;
  std::copy_if(regions_.begin(), regions_.end(), std::back_inserter(executable_regions), [](const memory_region& r) {
    return r.is_executable;
  });
  return executable_regions;
}

std::vector<memory_region> module_mapper::get_user_modules() const {
  std::vector<memory_region> user_modules;
  std::copy_if(regions_.begin(), regions_.end(), std::back_inserter(user_modules), [this](const memory_region& r) {
    return r.is_executable && !is_system_module(r.name);
  });
  return user_modules;
}

void module_mapper::add_target_module_pattern(const std::string& pattern) {
  target_patterns_.push_back(pattern);
  log_.debug("added target module pattern", redlog::field("pattern", pattern));
}

void module_mapper::clear_target_patterns() {
  target_patterns_.clear();
  log_.debug("cleared target module patterns");
}

size_t module_mapper::get_executable_count() const {
  return std::count_if(regions_.begin(), regions_.end(), [](const memory_region& r) { return r.is_executable; });
}

size_t module_mapper::get_user_module_count() const {
  return std::count_if(regions_.begin(), regions_.end(), [this](const memory_region& r) {
    return r.is_executable && !is_system_module(r.name);
  });
}

bool module_mapper::discover_modules_darwin() {
  log_.debug("using darwin-specific module discovery");

  // darwin currently uses qbdi as primary method
  // could be enhanced with mach-o parsing and dyld info in the future
  bool success = discover_qbdi_modules();

  if (!success) {
    log_.warn("qbdi module discovery failed on darwin", redlog::field("pid", getpid()));
  }

  return success;
}

bool module_mapper::discover_modules_linux() {
  log_.debug("using linux-specific module discovery via /proc/self/maps");

  std::ifstream maps_file("/proc/self/maps");
  if (!maps_file) {
    int open_errno = errno;
    log_.error(
        "could not open /proc/self/maps", redlog::field("errno", open_errno),
        redlog::field("error", strerror(open_errno))
    );

    log_.info("falling back to qbdi module discovery");
    return discover_qbdi_modules();
  }

  size_t line_count = 0;
  size_t parsed_count = 0;
  size_t parse_errors = 0;
  std::string line;

  while (std::getline(maps_file, line)) {
    line_count++;

    // parse line format: address perms offset dev inode pathname
    std::istringstream iss(line);
    std::string address_range, perms, offset, dev, inode, pathname;

    if (!(iss >> address_range >> perms >> offset >> dev >> inode)) {
      parse_errors++;
      log_.trace("failed to parse maps line", redlog::field("line", line_count), redlog::field("content", line));
      continue;
    }

    // get optional pathname
    std::getline(iss, pathname);
    if (!pathname.empty() && pathname[0] == ' ') {
      pathname = pathname.substr(1); // remove leading space
    }

    // parse address range
    size_t dash_pos = address_range.find('-');
    if (dash_pos == std::string::npos) {
      parse_errors++;
      log_.trace(
          "invalid address range format", redlog::field("line", line_count), redlog::field("range", address_range)
      );
      continue;
    }

    try {
      uint64_t start = std::stoull(address_range.substr(0, dash_pos), nullptr, 16);
      uint64_t end = std::stoull(address_range.substr(dash_pos + 1), nullptr, 16);

      bool is_executable = (perms.length() > 2 && perms[2] == 'x');

      if (pathname.empty()) {
        pathname = "[anonymous]";
      }

      regions_.emplace_back(start, end, pathname, perms, is_executable);
      parsed_count++;

      log_.trace(
          "parsed memory region", redlog::field("start", start), redlog::field("end", end),
          redlog::field("perms", perms), redlog::field("name", pathname), redlog::field("executable", is_executable)
      );

    } catch (const std::exception& e) {
      parse_errors++;
      log_.warn(
          "failed to parse address range", redlog::field("line", line_count), redlog::field("range", address_range),
          redlog::field("error", e.what())
      );
    }
  }

  log_.info(
      "linux module discovery completed", redlog::field("lines", line_count), redlog::field("regions", parsed_count),
      redlog::field("errors", parse_errors)
  );

  if (parsed_count == 0) {
    log_.error("no memory regions parsed from /proc/self/maps");
    return false;
  }

  return true;
}

bool module_mapper::discover_modules_unix() {
  log_.debug("using generic unix module discovery");

  // fallback to qbdi method for generic unix
  return discover_qbdi_modules();
}

bool module_mapper::is_system_module(const std::string& path) const {
  // Use cross-platform system library detection
  return w1::common::platform_utils::is_system_library_path(path);
}

bool module_mapper::matches_target_pattern(const std::string& path) const {
  if (target_patterns_.empty()) {
    return true; // no patterns means include all
  }

  for (const auto& pattern : target_patterns_) {
    try {
      std::regex pattern_regex(pattern);
      if (std::regex_search(path, pattern_regex)) {
        return true;
      }
    } catch (const std::exception& e) {
      log_.warn("invalid regex pattern", redlog::field("pattern", pattern), redlog::field("error", e.what()));
    }
  }

  return false;
}

bool module_mapper::should_include_module(const memory_region& region) const {
  // only include executable regions
  if (!region.is_executable) {
    return false;
  }

  // exclude system modules if configured
  if (exclude_system_ && is_system_module(region.name)) {
    return false;
  }

  // check target patterns
  if (!matches_target_pattern(region.name)) {
    return false;
  }

  return true;
}

std::string module_mapper::parse_permissions(const std::string& perm_str) const {
  // normalize permission string format
  return perm_str;
}

bool module_mapper::convert_qbdi_memory_maps(const std::vector<QBDI::MemoryMap>& maps) {
  regions_.clear();

  size_t converted_count = 0;
  size_t skipped_count = 0;
  uint64_t total_memory = 0;
  uint64_t executable_memory = 0;

  for (const auto& map : maps) {
    try {
      bool is_executable = (map.permission & QBDI::PF_EXEC) != 0;

      std::string perm_str;
      if (map.permission & QBDI::PF_READ) {
        perm_str += "r";
      } else {
        perm_str += "-";
      }
      if (map.permission & QBDI::PF_WRITE) {
        perm_str += "w";
      } else {
        perm_str += "-";
      }
      if (map.permission & QBDI::PF_EXEC) {
        perm_str += "x";
      } else {
        perm_str += "-";
      }

      std::string name = !map.name.empty() ? map.name : std::string("[unknown]");

      uint64_t start_addr = static_cast<uint64_t>(map.range.start());
      uint64_t end_addr = static_cast<uint64_t>(map.range.end());
      uint64_t size = end_addr - start_addr;

      // validate address range
      if (start_addr >= end_addr) {
        log_.warn(
            "invalid memory range detected", redlog::field("start", start_addr), redlog::field("end", end_addr),
            redlog::field("name", name)
        );
        skipped_count++;
        continue;
      }

      regions_.emplace_back(start_addr, end_addr, name, perm_str, is_executable);
      converted_count++;

      total_memory += size;
      if (is_executable) {
        executable_memory += size;
      }

      log_.trace(
          "converted memory map", redlog::field("start", start_addr), redlog::field("end", end_addr),
          redlog::field("size", size), redlog::field("perms", perm_str), redlog::field("name", name),
          redlog::field("executable", is_executable)
      );

    } catch (const std::exception& e) {
      log_.warn("failed to convert memory map", redlog::field("error", e.what()));
      skipped_count++;
    }
  }

  log_.debug(
      "qbdi memory map conversion completed", redlog::field("input", maps.size()),
      redlog::field("converted", converted_count), redlog::field("skipped", skipped_count),
      redlog::field("total_bytes", total_memory), redlog::field("exec_bytes", executable_memory)
  );

  return converted_count > 0;
}

} // namespace w1::coverage