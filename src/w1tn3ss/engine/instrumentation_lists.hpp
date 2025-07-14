#pragma once

#include <string>
#include <vector>
#include <algorithm>

namespace w1 {

/**
 * platform-specific lists of modules that require special handling during instrumentation
 * these lists are derived from qbdi's preload conflict module handling
 */
class instrumentation_lists {
public:
  /**
   * modules that must never be instrumented to avoid crashes, infinite recursion, or instability
   * these are typically low-level system libraries that qbdi itself depends on
   */
  static std::vector<std::string> get_conflict_modules();

  /**
   * modules that must always be instrumented for stability
   * these are typically dynamic linker components needed for proper execution flow
   */
  static std::vector<std::string> get_critical_modules();

  /**
   * check if a module name matches any pattern in the list
   * supports partial matching (e.g., "libc-2." matches "libc-2.31.so")
   */
  static bool matches_any(const std::string& module_name, const std::vector<std::string>& patterns);

  /**
   * check if a module is a conflict module (should never be instrumented)
   */
  static bool is_conflict_module(const std::string& module_name);

  /**
   * check if a module is a critical module (must always be instrumented)
   */
  static bool is_critical_module(const std::string& module_name);
};

} // namespace w1