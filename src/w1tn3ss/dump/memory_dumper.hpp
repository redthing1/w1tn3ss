#pragma once

#include <QBDI.h>
#include <redlog.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/register_access.hpp>
#include <set>
#include "dump_format.hpp"

namespace w1 {
namespace dump {

struct dump_options {
  bool dump_memory_content = false; // include actual memory data

  struct filter {
    enum type { ALL, CODE, DATA, STACK };
    type region_type;
    std::set<std::string> modules; // empty = all modules
  };
  std::vector<filter> filters; // if empty when dump_memory_content=true, dump all

  uint64_t max_region_size = 100 * 1024 * 1024; // 100mb default limit
};

class memory_dumper {
public:
  // dump memory regions with classification
  static std::vector<memory_region> dump_memory_regions(
      QBDI::VMInstanceRef vm, const QBDI::GPRState& gpr, const dump_options& options = {}
  );

  // dump module information
  static std::vector<module_info_serializable> dump_modules(const dump_options& options = {});

private:
  static redlog::logger log_;

  // classify region based on observable characteristics
  static void classify_region(
      memory_region& region, const QBDI::MemoryMap& map, const std::vector<util::module_info>& modules,
      uint64_t stack_pointer
  );

  // check if region should be included based on filters
  static bool should_include_region(const memory_region& region, const dump_options& options);

  // safely read memory contents
  static std::vector<uint8_t> read_memory_region(QBDI::VMInstanceRef vm, uint64_t start, uint64_t size);
};

} // namespace dump
} // namespace w1