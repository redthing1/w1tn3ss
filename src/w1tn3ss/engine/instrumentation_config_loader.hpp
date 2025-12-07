#pragma once

#include "instrumentation_config.hpp"
#include <w1tn3ss/util/env_config.hpp>

namespace w1 {

// populate an instrumentation_config from environment variables using a given loader
inline void load_instrumentation_config_from_env(const util::env_config& loader, instrumentation_config& config) {
  config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
  config.use_default_conflicts = loader.get<bool>("USE_DEFAULT_CONFLICTS", true);
  config.use_default_criticals = loader.get<bool>("USE_DEFAULT_CRITICALS", true);
  config.verbose_instrumentation = loader.get<bool>("VERBOSE_INSTRUMENTATION", false);

  auto module_filter_env = loader.get_list("MODULE_FILTER");
  if (!module_filter_env.empty()) {
    config.module_filter = module_filter_env;
  }

  auto force_include_env = loader.get_list("FORCE_INCLUDE");
  if (!force_include_env.empty()) {
    config.force_include = force_include_env;
  }

  auto force_exclude_env = loader.get_list("FORCE_EXCLUDE");
  if (!force_exclude_env.empty()) {
    config.force_exclude = force_exclude_env;
  }
}

} // namespace w1
