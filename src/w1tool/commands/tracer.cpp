#include "tracer.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>

#include <redlog.hpp>

#include <w1base/platform_utils.hpp>
#include "tracer_discovery.hpp"
#include <w1nj3ct/w1nj3ct.hpp>
#include "w1base/signal_handler.hpp"

// forward declare CLI symbols from main.cpp
namespace cli {
extern args::CounterFlag verbosity_flag;
}

namespace w1tool::commands {

/**
 * convert tracer config key to environment variable name
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
 * parse config string in format "key=value"
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

bool apply_config_flags(
    args::ValueFlagList<std::string>& config_flags, std::map<std::string, std::string>& config_map,
    std::string* error_out
) {
  if (!config_flags) {
    return true;
  }

  for (const std::string& config_str : args::get(config_flags)) {
    auto [key, value] = parse_config_string(config_str);

    if (key.empty() || value.empty()) {
      if (error_out) {
        *error_out = config_str;
      }
      return false;
    }

    config_map[key] = value;
  }

  return true;
}

void apply_debug_level(tracer_execution_params& params, args::ValueFlag<int>& debug_level_flag, int fallback_level) {
  if (debug_level_flag) {
    params.debug_level = args::get(debug_level_flag);
  } else {
    params.debug_level = fallback_level;
  }
}

bool apply_target(
    tracer_execution_params& params, const target_args& args, std::string* error_out, std::string_view name_flag
) {
  int target_count = 0;
  if (args.spawn_flag) {
    target_count++;
  }
  if (args.pid_flag) {
    target_count++;
  }
  if (args.name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    if (error_out) {
      *error_out = "exactly one target required: specify -s/--spawn, --pid, or " + std::string(name_flag);
    }
    return false;
  }

  if (args.suspended_flag && !args.spawn_flag) {
    if (error_out) {
      *error_out = "--suspended can only be used with -s/--spawn (launch tracing)";
    }
    return false;
  }

  if (args.no_aslr_flag && !args.spawn_flag) {
    if (error_out) {
      *error_out = "--no-aslr can only be used with -s/--spawn (launch tracing)";
    }
    return false;
  }

  if (args.spawn_flag) {
    if (args.args_list.Get().empty()) {
      if (error_out) {
        *error_out = "binary path required when using -s/--spawn flag";
      }
      return false;
    }

    std::vector<std::string> all_args = args::get(args.args_list);
    params.spawn_target = true;
    params.binary_path = all_args[0];
    params.suspended = args.suspended_flag;
    params.disable_aslr = args.no_aslr_flag;

    if (all_args.size() > 1) {
      params.binary_args.assign(all_args.begin() + 1, all_args.end());
    }
  } else if (args.pid_flag) {
    params.target_pid = args::get(args.pid_flag);
  } else if (args.name_flag) {
    params.process_name = args::get(args.name_flag);
  }

  return true;
}

std::string default_output_path(
    bool spawn_flag, args::PositionalList<std::string>& args_list, std::string_view suffix, std::string_view fallback
) {
  if (spawn_flag && !args_list.Get().empty()) {
    std::vector<std::string> all_args = args::get(args_list);
    std::filesystem::path fs_path(all_args[0]);
    std::string binary_name = fs_path.filename().string();
    return binary_name + std::string(suffix);
  }

  return std::string(fallback);
}

int tracer(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::Flag& spawn_flag,
    args::ValueFlag<int>& pid_flag, args::ValueFlag<std::string>& process_name_flag,
    args::ValueFlag<std::string>& output_flag, args::ValueFlagList<std::string>& config_flags,
    args::ValueFlag<int>& debug_level_flag, args::Flag& list_tracers_flag, args::Flag& suspended_flag,
    args::Flag& no_aslr_flag, args::PositionalList<std::string>& args_list, const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.tracer");

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

  // validate tracer name
  if (!name_flag) {
    log.err("tracer name required: specify -n/--name (use --list-tracers to see available options)");
    return 1;
  }

  const std::string tracer_name = args::get(name_flag);

  // build execution parameters
  tracer_execution_params params;
  params.tracer_name = tracer_name;
  params.executable_path = executable_path;

  if (library_flag) {
    params.library_path = args::get(library_flag);
  }

  // set debug level
  apply_debug_level(params, debug_level_flag, args::get(cli::verbosity_flag));

  // process config
  std::string config_error;
  if (!apply_config_flags(config_flags, params.config_map, &config_error)) {
    log.err("invalid config format, expected key=value", redlog::field("config", config_error));
    return 1;
  }

  // process output flag
  if (output_flag) {
    params.config_map["output"] = args::get(output_flag);
  }

  // set target
  std::string target_error;
  target_args target{spawn_flag, pid_flag, process_name_flag, suspended_flag, no_aslr_flag, args_list};
  if (!apply_target(params, target, &target_error, "--process-name")) {
    log.err(target_error);
    return 1;
  }

  return execute_tracer_impl(params);
}

int execute_tracer_impl(const tracer_execution_params& params) {
  auto log = redlog::get_logger("w1tool.tracer");

  // log platform info
  const std::string platform = w1::common::platform_utils::get_platform_name();
  log.debug("platform detected", redlog::field("platform", platform));

  if (!w1::common::platform_utils::supports_runtime_injection()) {
    log.warn("runtime injection may not be supported on this platform", redlog::field("platform", platform));
  }

  // initialize signal handling
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "w1tool";
  sig_config.log_signals = (args::get(cli::verbosity_flag) >= 1);

  w1::tn3ss::signal_handler::guard signal_guard(sig_config);
  if (!signal_guard.is_initialized()) {
    log.warn("failed to initialize signal handling system");
  }

  // register signal handler
  w1::tn3ss::signal_handler::register_handler(
      [](const std::string& context) {
        auto signal_log = redlog::get_logger("w1tool.signal");
        signal_log.info("received shutdown signal", redlog::field("context", context));
      },
      "tracer"
  );

  // determine library path
  std::string lib_path = params.library_path;
  if (lib_path.empty()) {
    // auto-discover path
    log.debug("attempting to auto-discover tracer library", redlog::field("tracer_name", params.tracer_name));

    lib_path = w1tool::tracer_discovery::find_tracer_library(params.executable_path, params.tracer_name);

    if (lib_path.empty()) {
      log.err("tracer library not found", redlog::field("tracer_name", params.tracer_name));
      log.info("use --list-tracers to see available options, or specify path with -L/--library");
      return 1;
    }

    log.info(
        "auto-discovered library", redlog::field("tracer_name", params.tracer_name), redlog::field("path", lib_path)
    );
  } else {
    log.debug("using explicit tracer library", redlog::field("path", lib_path));
  }

  // validate library path exists
  if (!std::filesystem::exists(lib_path)) {
    log.err("tracer library does not exist", redlog::field("path", lib_path));
    return 1;
  }

  // prepare injection configuration
  w1::inject::config cfg;
  cfg.library_path = lib_path;

  // set debug level for tracer
  std::string debug_env_var = make_env_var_name(params.tracer_name, "verbose");
  cfg.env_vars[debug_env_var] = std::to_string(params.debug_level);

  // add config entries
  for (const auto& [key, value] : params.config_map) {
    std::string env_var = make_env_var_name(params.tracer_name, key);
    cfg.env_vars[env_var] = value;

    log.debug(
        "added config", redlog::field("key", key), redlog::field("value", value), redlog::field("env_var", env_var)
    );
  }

  log.info(
      "tracer configuration", redlog::field("tracer", params.tracer_name), redlog::field("library", lib_path),
      redlog::field("debug_level", params.debug_level), redlog::field("env_vars_count", cfg.env_vars.size())
  );

  w1::inject::result result;

  // execute tracing
  if (params.spawn_target) {
    // launch tracing
    log.info(
        "starting launch-time tracing", redlog::field("tracer", params.tracer_name),
        redlog::field("binary", params.binary_path), redlog::field("args_count", params.binary_args.size()),
        redlog::field("suspended", params.suspended ? "true" : "false"),
        redlog::field("disable_aslr", params.disable_aslr ? "true" : "false")
    );

    cfg.injection_method = w1::inject::method::preload;
    cfg.binary_path = params.binary_path;
    cfg.args = params.binary_args;
    cfg.suspended = params.suspended;
    cfg.disable_aslr = params.disable_aslr;
    cfg.wait_for_completion = true;

    result = w1::inject::inject(cfg);

    // setup signal forwarding
    if (result.success() && result.target_pid > 0) {
      w1::tn3ss::signal_handler::setup_forwarding(result.target_pid);

      // register cleanup handler
      w1::tn3ss::signal_handler::register_cleanup(
          [target_pid = result.target_pid]() { w1::tn3ss::signal_handler::remove_forwarding(target_pid); },
          100, // high priority
          "tracer_cleanup_" + std::to_string(result.target_pid)
      );

      log.debug("signal forwarding established", redlog::field("target_pid", result.target_pid));
    }

  } else if (params.target_pid > 0) {
    // runtime tracing by pid
    log.info(
        "starting runtime tracing", redlog::field("tracer", params.tracer_name), redlog::field("method", "pid"),
        redlog::field("target_pid", params.target_pid)
    );

    cfg.injection_method = w1::inject::method::runtime;
    cfg.pid = params.target_pid;
    result = w1::inject::inject(cfg);

    // setup signal forwarding
    if (result.success() && result.target_pid > 0) {
      w1::tn3ss::signal_handler::setup_forwarding(result.target_pid);

      // register cleanup handler
      w1::tn3ss::signal_handler::register_cleanup(
          [target_pid = result.target_pid]() { w1::tn3ss::signal_handler::remove_forwarding(target_pid); },
          100, // high priority
          "tracer_cleanup_" + std::to_string(result.target_pid)
      );

      log.debug("signal forwarding established", redlog::field("target_pid", result.target_pid));
    }

  } else if (!params.process_name.empty()) {
    // runtime tracing by name
    log.info(
        "starting runtime tracing", redlog::field("tracer", params.tracer_name), redlog::field("method", "name"),
        redlog::field("process_name", params.process_name)
    );

    cfg.injection_method = w1::inject::method::runtime;
    cfg.process_name = params.process_name;
    result = w1::inject::inject(cfg);

    // setup signal forwarding
    if (result.success() && result.target_pid > 0) {
      w1::tn3ss::signal_handler::setup_forwarding(result.target_pid);

      // register cleanup handler
      w1::tn3ss::signal_handler::register_cleanup(
          [target_pid = result.target_pid]() { w1::tn3ss::signal_handler::remove_forwarding(target_pid); },
          100, // high priority
          "tracer_cleanup_" + std::to_string(result.target_pid)
      );

      log.debug("signal forwarding established", redlog::field("target_pid", result.target_pid));
    }
  } else {
    log.err("no valid target specified");
    return 1;
  }

  // handle result
  if (result.success()) {
    log.info("tracing completed successfully", redlog::field("tracer", params.tracer_name));
    if (result.target_pid > 0) {
      log.info("target process", redlog::field("pid", result.target_pid));
    }
    if (result.target_exit_code.has_value()) {
      log.info("target process exit code", redlog::field("exit_code", result.target_exit_code.value()));
    }

    std::cout << "tracing with " << params.tracer_name << " completed successfully.\n";
    if (result.target_exit_code.has_value()) {
      std::cout << "target process exited with code: " << result.target_exit_code.value() << "\n";
    }
    return 0;
  } else {
    log.err(
        "tracing failed", redlog::field("tracer", params.tracer_name), redlog::field("error", result.error_message)
    );
    return 1;
  }
}

} // namespace w1tool::commands
