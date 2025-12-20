#pragma once

#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/env_enumerator.hpp>
#include <w1tn3ss/engine/instrumentation_config.hpp>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <cctype>

namespace w1::tracers::script {

struct config : public w1::instrumentation_config {
  std::string script_path;
  bool verbose = false;

  // raw config values that can be passed to the script
  std::unordered_map<std::string, std::string> script_config;

  static config from_environment() {
    w1::util::env_config loader("W1SCRIPT_");

    config cfg;
    cfg.include_system_modules = loader.get<bool>("INCLUDE_SYSTEM", false);
    cfg.script_path = loader.get<std::string>("SCRIPT", "");
    cfg.verbose = loader.get<bool>("VERBOSE", false);
    cfg.module_filter = loader.get_list("MODULE_FILTER");
    cfg.force_include = loader.get_list("FORCE_INCLUDE");
    cfg.force_exclude = loader.get_list("FORCE_EXCLUDE");
    cfg.use_default_conflicts = loader.get<bool>("USE_DEFAULT_CONFLICTS", true);
    cfg.use_default_criticals = loader.get<bool>("USE_DEFAULT_CRITICALS", true);
    cfg.verbose_instrumentation = loader.get<bool>("VERBOSE_INSTRUMENTATION", false);

    // collect all W1SCRIPT_* environment variables for the script
    auto env_vars = w1::util::env_enumerator::get_vars_with_prefix("W1SCRIPT_");
    for (const auto& [key, value] : env_vars) {
      // skip the built-in ones
      if (key != "SCRIPT" && key != "VERBOSE" && key != "INCLUDE_SYSTEM" && key != "MODULE_FILTER" &&
          key != "FORCE_INCLUDE" && key != "FORCE_EXCLUDE" && key != "USE_DEFAULT_CONFLICTS" &&
          key != "USE_DEFAULT_CRITICALS" && key != "VERBOSE_INSTRUMENTATION") {
        // convert key to lowercase for consistency
        std::string lower_key = key;
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), [](unsigned char c) {
          return std::tolower(c);
        });
        cfg.script_config[lower_key] = value;
      }
    }

    return cfg;
  }

  bool is_valid() const { return !script_path.empty(); }
};

} // namespace w1::tracers::script
