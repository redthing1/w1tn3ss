#pragma once

#include <w1tn3ss/engine/instrumentation_config.hpp>
#include <w1tn3ss/util/env_config.hpp>

namespace threadtest {

struct threadtest_config : public w1::instrumentation_config {
  int verbose = 0;
  bool enable_thread_hooks = true;

  static threadtest_config from_environment() {
    w1::util::env_config loader("THREADTEST_");

    threadtest_config config;
    config.verbose = loader.get<int>("VERBOSE", 0);
    config.enable_thread_hooks = loader.get<bool>("ENABLE_THREAD_HOOKS", true);
    config.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);

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

    config.use_default_conflicts = loader.get<bool>("USE_DEFAULT_CONFLICTS", true);
    config.use_default_criticals = loader.get<bool>("USE_DEFAULT_CRITICALS", true);
    config.verbose_instrumentation = loader.get<bool>("VERBOSE_INSTRUMENTATION", false);

    return config;
  }
};

} // namespace threadtest
