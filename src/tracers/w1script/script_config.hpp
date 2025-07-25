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

    // collect all W1SCRIPT_* environment variables for the script
    auto env_vars = w1::util::env_enumerator::get_vars_with_prefix("W1SCRIPT_");
    for (const auto& [key, value] : env_vars) {
      // skip the built-in ones
      if (key != "SCRIPT" && key != "VERBOSE") {
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