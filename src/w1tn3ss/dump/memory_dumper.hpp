#pragma once

#include "w1tn3ss/dump/dump_format.hpp"
#include "w1tn3ss/util/memory_reader.hpp"

#include <QBDI.h>
#include <redlog.hpp>

#include <string>
#include <unordered_set>
#include <vector>

namespace w1::dump {

struct dump_options {
  bool dump_memory_content = false;

  struct filter {
    enum class region_type { all, code, data, stack };
    region_type type = region_type::all;
    std::unordered_set<std::string> modules;
  };

  std::vector<filter> filters;
  uint64_t max_region_size = 100 * 1024 * 1024;
};

class memory_dumper {
public:
  static std::vector<memory_region> dump_memory_regions(
      QBDI::VMInstanceRef vm, const util::memory_reader& memory, const QBDI::GPRState& gpr,
      const dump_options& options = {}
  );

  static std::vector<module_info> dump_modules();

private:
  static redlog::logger log_;

  static void classify_region(memory_region& region, const QBDI::MemoryMap& map, uint64_t stack_pointer);
  static bool should_include_region(const memory_region& region, const dump_options& options);
  static std::vector<uint8_t> read_memory_region(const util::memory_reader& memory, uint64_t start, uint64_t size);
  static std::string extract_basename(const std::string& path);
};

} // namespace w1::dump
