#pragma once

#include "w1base/ext/args.hpp"
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace w1tool::commands {

/**
 * convert tracer config key to environment variable name
 */
std::string make_env_var_name(const std::string& tracer_name, const std::string& config_key);

/**
 * parse config string in format "key=value"
 */
std::pair<std::string, std::string> parse_config_string(const std::string& config_str);

/**
 * apply config key=value flags into config map
 * returns false and sets error_out to the bad entry on parse failure
 */
bool apply_config_flags(
    args::ValueFlagList<std::string>& config_flags, std::map<std::string, std::string>& config_map,
    std::string* error_out = nullptr
);

/**
 * tracer execution parameters
 */
struct tracer_execution_params {
  std::string tracer_name;
  std::string library_path; // optional, empty for auto-discovery
  std::map<std::string, std::string> config_map;
  int debug_level = 0;

  // target specification (exactly one should be set)
  bool spawn_target = false;
  std::string binary_path;
  std::vector<std::string> binary_args;
  bool suspended = false;
  bool disable_aslr = false;

  int target_pid = -1;
  std::string process_name;

  std::string executable_path; // for auto-discovery
};

/**
 * execute tracer with given parameters (shared implementation)
 */
int execute_tracer_impl(const tracer_execution_params& params);

/**
 * tracer command - generic tracer launcher with flexible configuration
 */
int tracer(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::Flag& spawn_flag,
    args::ValueFlag<int>& pid_flag, args::ValueFlag<std::string>& process_name_flag,
    args::ValueFlag<std::string>& output_flag, args::ValueFlagList<std::string>& config_flags,
    args::ValueFlag<int>& debug_level_flag, args::Flag& list_tracers_flag, args::Flag& suspended_flag,
    args::Flag& no_aslr_flag, args::PositionalList<std::string>& args_list, const std::string& executable_path
);

} // namespace w1tool::commands
