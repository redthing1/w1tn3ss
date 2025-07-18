#include "memory_dumper.hpp"
#include <w1tn3ss/util/safe_memory.hpp>
#include <algorithm>

namespace w1 {
namespace dump {

redlog::logger memory_dumper::log_ = redlog::get_logger("w1.dump.memory");

std::vector<memory_region> memory_dumper::dump_memory_regions(
    QBDI::VMInstanceRef vm, const QBDI::GPRState& gpr, const dump_options& options
) {

  log_.vrb("dumping memory regions");

  // first get module info for classification
  util::module_scanner scanner;
  auto modules = scanner.scan_executable_modules();

  // get all memory maps
  auto maps = QBDI::getCurrentProcessMaps(false);
  std::vector<memory_region> regions;
  regions.reserve(maps.size());

  // get current stack pointer for classification
  uint64_t stack_pointer = w1::registers::get_sp(&gpr);

  for (const auto& map : maps) {
    memory_region region;
    region.start = map.range.start();
    region.end = map.range.end();
    region.permissions = static_cast<uint32_t>(map.permission);

    // classify the region
    classify_region(region, map, modules, stack_pointer);

    // check if we should include this region
    if (should_include_region(region, options)) {
      // dump memory content if requested
      if (options.dump_memory_content) {
        uint64_t size = region.end - region.start;

        // skip regions that are too large
        if (size > options.max_region_size) {
          log_.warn(
              "region too large, skipping memory content", redlog::field("start", "0x%llx", region.start),
              redlog::field("size", size), redlog::field("max", options.max_region_size)
          );
          // still include the region metadata, just not the content
        } else {
          region.data = read_memory_region(vm, region.start, size);
        }
      }

      regions.push_back(region);
    }
  }

  log_.inf("dumped memory regions", redlog::field("count", regions.size()));
  return regions;
}

std::vector<module_info_serializable> memory_dumper::dump_modules(const dump_options& options) {

  log_.vrb("dumping module information");

  util::module_scanner scanner;
  auto all_modules = scanner.scan_executable_modules();

  std::vector<module_info_serializable> result;
  result.reserve(all_modules.size());

  // always include all modules for metadata
  for (const auto& mod : all_modules) {
    module_info_serializable serializable;
    serializable.path = mod.path;
    serializable.name = mod.name;
    serializable.base_address = mod.base_address;
    serializable.size = mod.size;

    // convert module type enum to string
    switch (mod.type) {
    case util::module_type::MAIN_EXECUTABLE:
      serializable.type = "main_executable";
      break;
    case util::module_type::SHARED_LIBRARY:
      serializable.type = "shared_library";
      break;
    case util::module_type::ANONYMOUS_EXECUTABLE:
      serializable.type = "anonymous_executable";
      break;
    default:
      serializable.type = "unknown";
      break;
    }

    serializable.is_system_library = mod.is_system_library;
    serializable.permissions = static_cast<uint32_t>(mod.permission);

    result.push_back(serializable);
  }

  log_.inf("dumped modules", redlog::field("total", all_modules.size()), redlog::field("included", result.size()));

  return result;
}

void memory_dumper::classify_region(
    memory_region& region, const QBDI::MemoryMap& map, const std::vector<util::module_info>& modules,
    uint64_t stack_pointer
) {

  // check if it's the stack
  if (stack_pointer >= region.start && stack_pointer < region.end) {
    region.is_stack = true;
    log_.ped(
        "identified stack region", redlog::field("start", "0x%llx", region.start),
        redlog::field("end", "0x%llx", region.end)
    );
    return;
  }

  // check if it belongs to a module
  bool belongs_to_module = false;
  for (const auto& mod : modules) {
    if (region.start >= mod.base_address && region.start < mod.base_address + mod.size) {
      region.module_name = mod.name;
      belongs_to_module = true;
      break;
    }
  }

  // classify based on permissions only
  if (map.permission & QBDI::PF_EXEC) {
    region.is_code = true;
  } else {
    region.is_data = true; // all non-executable regions are data
  }

  log_.ped(
      "classified region", redlog::field("start", "0x%llx", region.start),
      redlog::field("permissions", "%d", region.permissions), redlog::field("module", region.module_name),
      redlog::field("is_stack", region.is_stack), redlog::field("is_code", region.is_code),
      redlog::field("is_data", region.is_data)
  );
}

bool memory_dumper::should_include_region(const memory_region& region, const dump_options& options) {

  // if not dumping memory content, include all regions for metadata
  if (!options.dump_memory_content) {
    return true;
  }

  // stack is always included when dumping memory
  if (region.is_stack) {
    return true;
  }

  // if no filters specified, include all regions
  if (options.filters.empty()) {
    return true;
  }

  // check each filter
  for (const auto& filter : options.filters) {
    bool type_matches = false;

    switch (filter.region_type) {
    case dump_options::filter::ALL:
      type_matches = true;
      break;
    case dump_options::filter::CODE:
      type_matches = region.is_code;
      break;
    case dump_options::filter::DATA:
      type_matches = region.is_data;
      break;
    case dump_options::filter::STACK:
      type_matches = region.is_stack;
      break;
    }

    if (!type_matches) {
      continue;
    }

    // if no module filter, it's a match
    if (filter.modules.empty()) {
      return true;
    }

    // check module filter
    for (const auto& mod : filter.modules) {
      // special case: _anon matches regions without module
      if (mod == "_anon") {
        if (region.module_name.empty()) {
          return true;
        }
      } else {
        // normal module name matching
        if (!region.module_name.empty() && region.module_name.find(mod) != std::string::npos) {
          return true;
        }
      }
    }
  }

  return false;
}

std::vector<uint8_t> memory_dumper::read_memory_region(QBDI::VMInstanceRef vm, uint64_t start, uint64_t size) {
  std::vector<uint8_t> data;
  data.resize(size);

  // use safe memory read_buffer
  auto buffer_result = util::safe_memory::read_buffer(vm, start, size, size);

  if (buffer_result && buffer_result->complete) {
    data = std::move(buffer_result->data);
  } else {
    log_.err("failed to read memory region", redlog::field("start", "0x%llx", start), redlog::field("size", size));
    data.clear();
  }

  return data;
}

} // namespace dump
} // namespace w1