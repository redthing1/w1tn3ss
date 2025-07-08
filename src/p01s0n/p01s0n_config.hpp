#pragma once

#include <string>
#include <cstdlib>
#include <cstring>

namespace p01s0n {

struct p01s0n_config {
  int verbose = 0;
  std::string output_dir = "";
  bool log_api_calls = true;
  bool dump_on_signal = true;

  static p01s0n_config from_environment() {
    p01s0n_config config;

    // parse verbose level
    const char* verbose_env = std::getenv("POISON_VERBOSE");
    if (verbose_env && strlen(verbose_env) > 0) {
      config.verbose = std::atoi(verbose_env);
    }

    // parse output directory
    const char* output_dir_env = std::getenv("POISON_OUTPUT_DIR");
    if (output_dir_env && strlen(output_dir_env) > 0) {
      config.output_dir = std::string(output_dir_env);
    }

    // parse api call logging flag
    const char* log_api_env = std::getenv("POISON_LOG_API_CALLS");
    if (log_api_env && strlen(log_api_env) > 0) {
      config.log_api_calls =
          (std::strcmp(log_api_env, "0") != 0 && std::strcmp(log_api_env, "false") != 0 &&
           std::strcmp(log_api_env, "FALSE") != 0);
    }

    // parse signal dump flag
    const char* dump_signal_env = std::getenv("POISON_DUMP_ON_SIGNAL");
    if (dump_signal_env && strlen(dump_signal_env) > 0) {
      config.dump_on_signal =
          (std::strcmp(dump_signal_env, "0") != 0 && std::strcmp(dump_signal_env, "false") != 0 &&
           std::strcmp(dump_signal_env, "FALSE") != 0);
    }

    return config;
  }
};

} // namespace p01s0n