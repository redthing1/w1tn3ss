#include "tracer.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>

#include <redlog/redlog.hpp>

#include "common/platform_utils.hpp"
#include "tracer_discovery.hpp"
#include "w1nj3ct.hpp"

// forward declare CLI symbols from main.cpp
namespace cli {
extern args::CounterFlag verbosity_flag;
}

namespace w1tool::commands {

/**
 * @brief Convert tracer config key to environment variable name
 * @param tracer_name name of tracer (e.g., "w1mem")
 * @param config_key config key (e.g., "verbose")
 * @return environment variable name (e.g., "W1MEM_VERBOSE")
 */
std::string make_env_var_name(const std::string& tracer_name, const std::string& config_key) {
  std::string env_name = tracer_name;

  // convert to uppercase
  std::transform(env_name.begin(), env_name.end(), env_name.begin(), ::toupper);

  // add config key in uppercase
  std::string upper_key = config_key;
  std::transform(upper_key.begin(), upper_key.end(), upper_key.begin(), ::toupper);

  return env_name + "_" + upper_key;
}

/**
 * @brief Parse config string in format "key=value"
 * @param config_str configuration string
 * @return pair of key and value, or empty strings if invalid format
 */
std::pair<std::string, std::string> parse_config_string(const std::string& config_str) {
  const size_t eq_pos = config_str.find('=');
  if (eq_pos == std::string::npos || eq_pos == 0 || eq_pos == config_str.length() - 1) {
    return {"", ""};
  }

  const std::string key = config_str.substr(0, eq_pos);
  const std::string value = config_str.substr(eq_pos + 1);

  return {key, value};
}

int tracer(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::Flag& spawn_flag,
    args::ValueFlag<int>& pid_flag, args::ValueFlag<std::string>& process_name_flag,
    args::ValueFlagList<std::string>& config_flags, args::ValueFlag<int>& debug_level_flag,
    args::Flag& list_tracers_flag, args::Flag& suspended_flag, args::PositionalList<std::string>& args_list,
    const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.tracer");

  // log platform information for debugging
  const std::string platform = w1::common::platform_utils::get_platform_name();
  log.debug("platform detected", redlog::field("platform", platform));

  if (!w1::common::platform_utils::supports_runtime_injection()) {
    log.warn("runtime injection may not be supported on this platform", redlog::field("platform", platform));
  }

  // handle --list-tracers flag
  if (list_tracers_flag) {
    const auto available_tracers = w1tool::tracer_discovery::list_available_tracers(executable_path);

    if (available_tracers.empty()) {
      std::cout << "no tracer libraries found\n";
      std::cout << "searched paths relative to: " << executable_path << "\n";
      return 0;
    }

    std::cout << "available tracers:\n";
    for (const auto& tracer : available_tracers) {
      std::cout << "  " << tracer.name << " - " << tracer.library_path << "\n";
    }
    return 0;
  }

  // validate tracer name is provided
  if (!name_flag) {
    log.err("tracer name required: specify -n/--name (use --list-tracers to see available options)");
    return 1;
  }

  const std::string tracer_name = args::get(name_flag);

  // determine library path - use specified path or auto-discover
  std::string lib_path;
  if (library_flag) {
    lib_path = args::get(library_flag);
    log.debug("using explicit tracer library", redlog::field("path", lib_path));
  } else {
    // auto-discover library path
    log.debug("attempting to auto-discover tracer library", redlog::field("tracer_name", tracer_name));

    lib_path = w1tool::tracer_discovery::find_tracer_library(executable_path, tracer_name);

    if (lib_path.empty()) {
      log.err("tracer library not found", redlog::field("tracer_name", tracer_name));
      log.info("use --list-tracers to see available options, or specify path with -L/--library");
      return 1;
    }

    log.info("auto-discovered library", redlog::field("tracer_name", tracer_name), redlog::field("path", lib_path));
  }

  // validate target specification
  int target_count = 0;
  if (spawn_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }
  if (process_name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.err("exactly one target required: specify -s/--spawn, --pid, or --process-name");
    return 1;
  }

  // validate suspended flag usage
  if (suspended_flag && !spawn_flag) {
    log.err("--suspended can only be used with -s/--spawn (launch tracing)");
    return 1;
  }

  // validate library path exists
  if (!std::filesystem::exists(lib_path)) {
    log.err("tracer library does not exist", redlog::field("path", lib_path));
    return 1;
  }

  // prepare injection configuration
  w1::inject::config cfg;
  cfg.library_path = lib_path;

  // set debug level: use override if provided, otherwise passthrough w1tool verbosity
  int effective_debug_level = 0;
  if (debug_level_flag) {
    effective_debug_level = args::get(debug_level_flag);
  } else {
    effective_debug_level = args::get(cli::verbosity_flag);
  }

  // always set the verbose/debug level for the tracer
  std::string debug_env_var = make_env_var_name(tracer_name, "verbose");
  cfg.env_vars[debug_env_var] = std::to_string(effective_debug_level);

  // process config flags
  if (config_flags) {
    for (const std::string& config_str : args::get(config_flags)) {
      auto [key, value] = parse_config_string(config_str);

      if (key.empty() || value.empty()) {
        log.err("invalid config format, expected key=value", redlog::field("config", config_str));
        return 1;
      }

      std::string env_var = make_env_var_name(tracer_name, key);
      cfg.env_vars[env_var] = value;

      log.debug(
          "added config", redlog::field("key", key), redlog::field("value", value), redlog::field("env_var", env_var)
      );
    }
  }

  log.info(
      "tracer configuration", redlog::field("tracer", tracer_name), redlog::field("library", lib_path),
      redlog::field("debug_level", effective_debug_level), redlog::field("env_vars_count", cfg.env_vars.size())
  );

  w1::inject::result result;

  // execute tracing based on target type
  if (spawn_flag) {
    // launch-time tracing with positional arguments
    if (args_list.Get().empty()) {
      log.err("binary path required when using -s/--spawn flag");
      return 1;
    }

    std::vector<std::string> all_args = args::get(args_list);
    std::string binary_path = all_args[0];

    // extract arguments after the binary (everything after first arg)
    std::vector<std::string> binary_args;
    if (all_args.size() > 1) {
      binary_args.assign(all_args.begin() + 1, all_args.end());
    }

    log.info(
        "starting launch-time tracing", redlog::field("tracer", tracer_name), redlog::field("binary", binary_path),
        redlog::field("args_count", binary_args.size()), redlog::field("suspended", suspended_flag ? "true" : "false")
    );

    cfg.injection_method = w1::inject::method::launch;
    cfg.binary_path = binary_path;
    cfg.args = binary_args;
    cfg.suspended = suspended_flag;
    cfg.wait_for_completion = true; // tracer command should wait for completion

    result = w1::inject::inject(cfg);

  } else if (pid_flag) {
    // runtime tracing by PID
    int target_pid = args::get(pid_flag);
    log.info(
        "starting runtime tracing", redlog::field("tracer", tracer_name), redlog::field("method", "pid"),
        redlog::field("target_pid", target_pid)
    );

    cfg.injection_method = w1::inject::method::runtime;
    cfg.pid = target_pid;
    result = w1::inject::inject(cfg);

  } else if (process_name_flag) {
    // runtime tracing by process name
    std::string process_name = args::get(process_name_flag);
    log.info(
        "starting runtime tracing", redlog::field("tracer", tracer_name), redlog::field("method", "name"),
        redlog::field("process_name", process_name)
    );

    cfg.injection_method = w1::inject::method::runtime;
    cfg.process_name = process_name;
    result = w1::inject::inject(cfg);
  }

  // handle result
  if (result.success()) {
    log.info("tracing completed successfully", redlog::field("tracer", tracer_name));
    if (result.target_pid > 0) {
      log.info("target process", redlog::field("pid", result.target_pid));
    }

    std::cout << "tracing with " << tracer_name << " completed successfully.\n";
    return 0;
  } else {
    log.err("tracing failed", redlog::field("tracer", tracer_name), redlog::field("error", result.error_message));
    return 1;
  }
}

} // namespace w1tool::commands