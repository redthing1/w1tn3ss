#pragma once

#include <string>
#include <vector>

namespace w1 {

/**
 * comprehensive configuration for controlling instrumentation behavior
 * provides fine-grained control over which modules are instrumented
 */
struct instrumentation_config {
  // basic filtering options

  /**
   * include system libraries in instrumentation (default: false)
   * when false, platform-specific system libraries are excluded
   */
  bool include_system_modules = false;

  /**
   * module filter patterns (if non-empty, only matching modules are instrumented)
   * supports partial string matching (e.g., "myapp" matches "libmyapp.so")
   * note: critical modules are always included regardless of filter
   */
  std::vector<std::string> module_filter;

  // advanced options

  /**
   * force include patterns - modules matching these are always instrumented
   * overrides all other exclusion rules except conflict modules
   */
  std::vector<std::string> force_include;

  /**
   * force exclude patterns - modules matching these are never instrumented
   * useful for custom exclusions beyond the default conflict list
   */
  std::vector<std::string> force_exclude;

  // platform defaults

  /**
   * use default platform-specific conflict module list (default: true)
   * when true, modules known to cause issues are automatically excluded
   */
  bool use_default_conflicts = true;

  /**
   * use default platform-specific critical module list (default: true)
   * when true, modules required for stability are automatically included
   */
  bool use_default_criticals = true;

  // debugging options

  /**
   * log detailed information about instrumentation decisions (default: false)
   */
  bool verbose_instrumentation = false;
};

} // namespace w1