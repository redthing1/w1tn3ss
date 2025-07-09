#pragma once

#include <string>
#include <QBDI.h>

namespace w1 {
namespace util {

enum class module_type { UNKNOWN, MAIN_EXECUTABLE, SHARED_LIBRARY, ANONYMOUS_EXECUTABLE };

struct module_info {
  std::string path; // path to the file on disk, if available
  std::string name; // module basename
  QBDI::rword base_address;
  size_t size;
  module_type type;
  bool is_system_library; // determined by platform-specific heuristics.
};

} // namespace util
} // namespace w1