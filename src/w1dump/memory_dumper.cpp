#include "w1dump/memory_dumper.hpp"

#include <algorithm>

#include "w1runtime/module_catalog.hpp"

namespace w1::dump {

redlog::logger memory_dumper::log_ = redlog::get_logger("w1.dump.memory");

std::vector<memory_region> memory_dumper::dump_memory_regions(
    QBDI::VMInstanceRef vm, const util::memory_reader& memory, const QBDI::GPRState& gpr, const dump_options& options
) {
  log_.vrb("dumping memory regions");
  (void) vm;

  auto maps = QBDI::getCurrentProcessMaps(false);
  log_.dbg("retrieved memory maps", redlog::field("count", maps.size()));

  std::vector<memory_region> regions;
  regions.reserve(maps.size());

  uint64_t stack_pointer = QBDI_GPR_GET(&gpr, QBDI::REG_SP);

  for (const auto& map : maps) {
    memory_region region;
    region.start = map.range.start();
    region.end = map.range.end();
    region.permissions = static_cast<uint32_t>(map.permission);

    classify_region(region, map, stack_pointer);

    if (!should_include_region(region, options)) {
      continue;
    }

    uint64_t size = region.end > region.start ? region.end - region.start : 0;
    if (options.dump_memory_content) {
      bool should_dump_content = true;
      if (size > options.max_region_size && !region.is_stack) {
        should_dump_content = false;
      }

      if (should_dump_content && size > 0) {
        region.data = read_memory_region(memory, region.start, size);
      }
    }

    regions.push_back(std::move(region));
  }

  log_.inf("dumped memory regions", redlog::field("included", regions.size()), redlog::field("total", maps.size()));

  return regions;
}

std::vector<module_info> memory_dumper::dump_modules() {
  log_.vrb("dumping module information");

  runtime::module_catalog registry;
  registry.refresh();
  auto runtime_modules = registry.list_modules();

  std::vector<module_info> modules;
  modules.reserve(runtime_modules.size());

  for (const auto& module : runtime_modules) {
    if (module.size == 0) {
      continue;
    }
    if (module.name.rfind("_unnamed_", 0) == 0) {
      continue;
    }

    module_info info;
    info.path = module.path.empty() ? module.name : module.path;
    info.name = module.name.empty() ? info.path : module.name;
    info.base_address = module.base_address;
    info.size = module.size;
    info.type = "unknown";
    info.is_system = module.is_system;
    info.permissions = module.permissions;

    modules.push_back(std::move(info));
  }

  std::sort(modules.begin(), modules.end(), [](const module_info& left, const module_info& right) {
    return left.base_address < right.base_address;
  });

  log_.inf("dumped modules", redlog::field("total", modules.size()));

  return modules;
}

void memory_dumper::classify_region(memory_region& region, const QBDI::MemoryMap& map, uint64_t stack_pointer) {
  region.module_name = map.name.empty() ? "" : extract_basename(map.name);
  region.is_anonymous = region.module_name.empty();

  if (stack_pointer >= region.start && stack_pointer < region.end) {
    region.is_stack = true;
  }

  if (map.permission & QBDI::PF_EXEC) {
    region.is_code = true;
  } else {
    region.is_data = true;
  }
}

bool memory_dumper::should_include_region(const memory_region& region, const dump_options& options) {
  if (!options.dump_memory_content) {
    return true;
  }

  if (region.is_stack) {
    return true;
  }

  if (options.filters.empty()) {
    return true;
  }

  for (const auto& filter : options.filters) {
    bool type_matches = false;
    switch (filter.type) {
    case dump_options::filter::region_type::all:
      type_matches = true;
      break;
    case dump_options::filter::region_type::code:
      type_matches = region.is_code;
      break;
    case dump_options::filter::region_type::data:
      type_matches = region.is_data;
      break;
    case dump_options::filter::region_type::stack:
      type_matches = region.is_stack;
      break;
    }

    if (!type_matches) {
      continue;
    }

    if (filter.modules.empty()) {
      return true;
    }

    for (const auto& mod : filter.modules) {
      if (mod == "_anon") {
        if (region.module_name.empty()) {
          return true;
        }
      } else {
        if (!region.module_name.empty() && region.module_name.find(mod) != std::string::npos) {
          return true;
        }
      }
    }
  }

  return false;
}

std::vector<uint8_t> memory_dumper::read_memory_region(
    const util::memory_reader& memory, uint64_t start, uint64_t size
) {
  if (size == 0) {
    return {};
  }

  auto bytes = memory.read_bytes(start, static_cast<size_t>(size));
  if (!bytes) {
    log_.err("failed to read memory region", redlog::field("start", "0x%llx", start));
    return {};
  }

  return *bytes;
}

std::string memory_dumper::extract_basename(const std::string& path) {
  if (path.empty()) {
    return path;
  }

  size_t pos = path.find_last_of("/\\");
  if (pos != std::string::npos) {
    return path.substr(pos + 1);
  }

  return path;
}

} // namespace w1::dump
