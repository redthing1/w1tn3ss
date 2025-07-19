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
  log_.trc("scanning executable modules for region classification");
  util::module_scanner scanner;
  auto modules = scanner.scan_executable_modules();
  log_.dbg("found modules for classification", redlog::field("count", modules.size()));

  // get all memory maps
  log_.trc("retrieving current process memory maps");
  auto maps = QBDI::getCurrentProcessMaps(false);
  log_.dbg("retrieved memory maps", redlog::field("count", maps.size()));

  // log filter configuration
  if (options.dump_memory_content && !options.filters.empty()) {
    log_.dbg("applying memory region filters", redlog::field("filter_count", options.filters.size()));
    for (size_t i = 0; i < options.filters.size(); ++i) {
      const auto& filter = options.filters[i];
      std::string type_str = filter.region_type == dump_options::filter::ALL
                                 ? "ALL"
                                 : (filter.region_type == dump_options::filter::CODE
                                        ? "CODE"
                                        : (filter.region_type == dump_options::filter::DATA ? "DATA" : "STACK"));
      log_.dbg(
          "filter configuration", redlog::field("index", i), redlog::field("type", type_str),
          redlog::field("module_count", filter.modules.size())
      );
    }
  }

  std::vector<memory_region> regions;
  regions.reserve(maps.size());

  // get current stack pointer for classification
  uint64_t stack_pointer = w1::registers::get_sp(&gpr);

  for (const auto& map : maps) {
    memory_region region;
    region.start = map.range.start();
    region.end = map.range.end();
    region.permissions = static_cast<uint32_t>(map.permission);

    log_.ped(
        "processing memory map", redlog::field("start", "0x%llx", region.start),
        redlog::field("end", "0x%llx", region.end), redlog::field("size", region.end - region.start)
    );

    // classify the region
    classify_region(region, map, modules, stack_pointer);

    // check if we should include this region
    bool include = should_include_region(region, options);
    if (include) {
      uint64_t size = region.end - region.start;
      std::string status = "including region";

      // dump memory content if requested
      if (options.dump_memory_content) {
        bool should_dump_content = true;

        // check size limit (stack always gets dumped regardless of size)
        if (size > options.max_region_size) {
          if (region.is_stack) {
            // stack bypasses size limit
            log_.wrn(
                "dumping large stack region (bypassing size limit)", redlog::field("start", "0x%llx", region.start),
                redlog::field("size", size), redlog::field("size_mb", size / (1024 * 1024))
            );
          } else {
            // non-stack regions that are too large get metadata only
            should_dump_content = false;
            status = "including region (metadata only, too large)";
            log_.wrn(
                "region too large for content dump", redlog::field("start", "0x%llx", region.start),
                redlog::field("size", size), redlog::field("max", options.max_region_size)
            );
          }
        }

        // dump content if appropriate
        if (should_dump_content) {
          region.data = read_memory_region(vm, region.start, size);
          if (region.data.empty()) {
            status = "including region (content read failed)";
          }
        }
      }

      log_.dbg(
          status.c_str(), redlog::field("start", "0x%llx", region.start), redlog::field("size", size),
          redlog::field("module", region.module_name.empty() ? "<anon>" : region.module_name),
          redlog::field("type", region.is_stack ? "stack" : (region.is_code ? "code" : "data"))
      );

      regions.push_back(region);
    } else {
      log_.dbg(
          "excluding region", redlog::field("start", "0x%llx", region.start),
          redlog::field("size", region.end - region.start),
          redlog::field("module", region.module_name.empty() ? "<anon>" : region.module_name),
          redlog::field("type", region.is_stack ? "stack" : (region.is_code ? "code" : "data"))
      );
    }
  }

  // summary of included/excluded regions
  size_t total_regions = maps.size();
  size_t included_regions = regions.size();
  size_t excluded_regions = total_regions - included_regions;

  log_.inf(
      "dumped memory regions", redlog::field("included", included_regions), redlog::field("excluded", excluded_regions),
      redlog::field("total", total_regions)
  );

  // calculate total memory size included
  uint64_t total_size = 0;
  for (const auto& region : regions) {
    total_size += (region.end - region.start);
  }
  log_.dbg(
      "total memory size included", redlog::field("bytes", total_size), redlog::field("mb", total_size / (1024 * 1024))
  );

  return regions;
}

std::vector<module_info_serializable> memory_dumper::dump_modules(const dump_options& options) {

  log_.vrb("dumping module information");

  log_.trc("scanning all executable modules");
  util::module_scanner scanner;
  auto all_modules = scanner.scan_executable_modules();
  log_.dbg("module scan complete", redlog::field("total_modules", all_modules.size()));

  std::vector<module_info_serializable> result;
  result.reserve(all_modules.size());

  // always include all modules for metadata
  log_.trc("converting modules to serializable format");
  for (const auto& mod : all_modules) {
    log_.ped(
        "processing module", redlog::field("name", mod.name), redlog::field("base", "0x%llx", mod.base_address),
        redlog::field("size", mod.size)
    );
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

  log_.dbg("module serialization complete");

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
    log_.ped("including region for metadata only", redlog::field("start", "0x%llx", region.start));
    return true;
  }

  // stack is always included when dumping memory
  if (region.is_stack) {
    log_.ped("including stack region", redlog::field("start", "0x%llx", region.start));
    return true;
  }

  // if no filters specified, include all regions
  if (options.filters.empty()) {
    log_.ped("no filters specified, including region", redlog::field("start", "0x%llx", region.start));
    return true;
  }

  // check each filter
  for (const auto& filter : options.filters) {
    bool type_matches = false;

    switch (filter.region_type) {
    case dump_options::filter::ALL:
      type_matches = true;
      log_.ped("filter matches ALL type");
      break;
    case dump_options::filter::CODE:
      type_matches = region.is_code;
      if (type_matches) {
        log_.ped("filter matches CODE type");
      }
      break;
    case dump_options::filter::DATA:
      type_matches = region.is_data;
      if (type_matches) {
        log_.ped("filter matches DATA type");
      }
      break;
    case dump_options::filter::STACK:
      type_matches = region.is_stack;
      if (type_matches) {
        log_.ped("filter matches STACK type");
      }
      break;
    }

    if (!type_matches) {
      continue;
    }

    // if no module filter, it's a match
    if (filter.modules.empty()) {
      log_.ped(
          "region matches filter (no module constraint)", redlog::field("start", "0x%llx", region.start),
          redlog::field(
              "filter_type", filter.region_type == dump_options::filter::ALL
                                 ? "ALL"
                                 : (filter.region_type == dump_options::filter::CODE
                                        ? "CODE"
                                        : (filter.region_type == dump_options::filter::DATA ? "DATA" : "STACK"))
          )
      );
      return true;
    }

    // check module filter
    for (const auto& mod : filter.modules) {
      // special case: _anon matches regions without module
      if (mod == "_anon") {
        if (region.module_name.empty()) {
          log_.ped("region matches _anon filter", redlog::field("start", "0x%llx", region.start));
          return true;
        }
      } else {
        // normal module name matching
        if (!region.module_name.empty() && region.module_name.find(mod) != std::string::npos) {
          log_.ped(
              "region matches module filter", redlog::field("start", "0x%llx", region.start),
              redlog::field("module", region.module_name), redlog::field("filter", mod)
          );
          return true;
        }
      }
    }
  }

  log_.ped("region does not match any filter", redlog::field("start", "0x%llx", region.start));
  return false;
}

std::vector<uint8_t> memory_dumper::read_memory_region(QBDI::VMInstanceRef vm, uint64_t start, uint64_t size) {
  log_.ped("reading memory region", redlog::field("start", "0x%llx", start), redlog::field("size", size));

  std::vector<uint8_t> data;
  data.resize(size);

  // use safe memory read_buffer
  auto buffer_result = util::safe_memory::read_buffer(vm, start, size, size);

  if (buffer_result && buffer_result->complete) {
    data = std::move(buffer_result->data);
    log_.ped("memory region read complete", redlog::field("bytes_read", data.size()));
  } else {
    log_.err("failed to read memory region", redlog::field("start", "0x%llx", start), redlog::field("size", size));
    if (buffer_result) {
      log_.dbg(
          "partial read", redlog::field("complete", buffer_result->complete),
          redlog::field("bytes_read", buffer_result->data.size())
      );
    }
    data.clear();
  }

  return data;
}

} // namespace dump
} // namespace w1