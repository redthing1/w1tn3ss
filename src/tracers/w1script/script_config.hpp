#pragma once

#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/env_enumerator.hpp>
#include <string>
#include <unordered_map>

namespace w1::tracers::script {

struct config {
  std::string script_path;
  bool verbose = false;

  // raw config values that can be passed to the script
  std::unordered_map<std::string, std::string> script_config;

  static config from_environment() {
    w1::util::env_config loader("W1SCRIPT_");

    config cfg;
    cfg.script_path = loader.get<std::string>("SCRIPT", "");
    cfg.verbose = loader.get<bool>("VERBOSE", false);

    // collect all W1SCRIPT_* environment variables for the script
    auto env_vars = w1::util::env_enumerator::get_vars_with_prefix("W1SCRIPT_");
    for (const auto& [key, value] : env_vars) {
      // skip the built-in ones
      if (key != "SCRIPT" && key != "VERBOSE") {
        cfg.script_config[key] = value;
      }
    }

    return cfg;
  }

  bool is_valid() const { return !script_path.empty(); }
};

} // namespace w1::tracers::script