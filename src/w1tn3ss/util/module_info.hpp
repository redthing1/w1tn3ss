#pragma once

#include <string>
#include <QBDI.h>

namespace w1 {
namespace util {

enum class module_type { UNKNOWN, MAIN_EXECUTABLE, SHARED_LIBRARY, ANONYMOUS_EXECUTABLE };

struct module_info {
  std::string path; // path to the file on disk, if available
  std::string name; // module basename
  QBDI::rword base_address = 0;
  size_t size = 0;
  module_type type = module_type::UNKNOWN;
  bool is_system_library = false;              // determined by platform-specific heuristics.
  QBDI::Range<QBDI::rword> range{0, 0};        // memory range for direct instrumentation
  QBDI::Permission permission = QBDI::PF_NONE; // memory permissions
};

} // namespace util
} // namespace w1