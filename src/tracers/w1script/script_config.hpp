#pragma once

#include <w1tn3ss/util/env_config.hpp>
#include <string>
#include <unordered_map>

extern char** environ;

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
    if (char** env_ptr = environ) {
      for (char** env = env_ptr; *env != nullptr; env++) {
        std::string env_var(*env);
        if (env_var.find("W1SCRIPT_") == 0) {
          size_t eq_pos = env_var.find('=');
          if (eq_pos != std::string::npos) {
            std::string key = env_var.substr(10, eq_pos - 10); // Skip "W1SCRIPT_"
            std::string value = env_var.substr(eq_pos + 1);

            // skip the built-in ones
            if (key != "SCRIPT" && key != "VERBOSE") {
              cfg.script_config[key] = value;
            }
          }
        }
      }
    }

    return cfg;
  }

  bool is_valid() const { return !script_path.empty(); }
};

} // namespace w1::tracers::script