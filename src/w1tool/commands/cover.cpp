#include "cover.hpp"
#include "tracer.hpp"
#include "w1base/ext/args.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <redlog.hpp>

// forward declare CLI symbols from main.cpp
namespace cli {
extern args::CounterFlag verbosity_flag;
}

namespace w1tool::commands {

int cover(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag,
    args::ValueFlag<std::string>& system_policy_flag, args::Flag& inst_trace_flag,
    args::ValueFlagList<std::string>& config_flags, args::ValueFlag<std::string>& module_filter_flag,
    args::ValueFlag<int>& debug_level_flag, args::ValueFlag<std::string>& format_flag, args::Flag& suspended_flag,
    args::Flag& no_aslr_flag, args::PositionalList<std::string>& args_list, const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.cover");

  // validate output format
  std::string format = "drcov"; // default
  if (format_flag) {
    format = args::get(format_flag);
    if (format != "drcov" && format != "text") {
      log.err("invalid format, supported: drcov, text", redlog::field("format", format));
      return 1;
    }
    if (format == "text") {
      log.warn("text format not yet implemented, using drcov format");
      format = "drcov";
    }
  }

  // build execution parameters
  tracer_execution_params params;
  params.tracer_name = "w1cov";
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

  // determine output file
  std::string output_file;
  if (output_flag) {
    output_file = args::get(output_flag);
  } else if (auto it = params.config_map.find("output"); it != params.config_map.end()) {
    output_file = it->second;
  } else {
    output_file = default_output_path(
        spawn_flag, args_list, std::string("_coverage.") + format, std::string("coverage.") + format
    );
  }

  // translate cover flags to w1cov config
  if (system_policy_flag) {
    params.config_map["system_policy"] = args::get(system_policy_flag);
  }
  if (inst_trace_flag) {
    params.config_map["mode"] = "instruction";
  } else if (params.config_map.find("mode") == params.config_map.end()) {
    params.config_map["mode"] = "basic_block";
  }
  params.config_map["output"] = output_file;

  if (module_filter_flag) {
    params.config_map["module_filter"] = args::get(module_filter_flag);
  }

  // set target
  std::string target_error;
  target_args target{spawn_flag, pid_flag, name_flag, suspended_flag, no_aslr_flag, args_list};
  if (!apply_target(params, target, &target_error)) {
    log.err(target_error);
    return 1;
  }

  std::string system_policy = "default";
  if (auto it = params.config_map.find("system_policy"); it != params.config_map.end()) {
    system_policy = it->second;
  }
  std::string mode = "basic_block";
  if (auto it = params.config_map.find("mode"); it != params.config_map.end()) {
    mode = it->second;
  }
  log.info(
      "coverage tracing configuration", redlog::field("output_file", output_file), redlog::field("format", format),
      redlog::field("system_policy", system_policy), redlog::field("mode", mode),
      redlog::field("debug_level", params.debug_level)
  );

  // execute w1cov tracing
  int result = execute_tracer_impl(params);

  // handle cover post-processing
  if (result == 0) {
    // check output file created
    if (!std::filesystem::exists(output_file)) {
      log.err("output file not created", redlog::field("output_file", output_file));
      return 1;
    }

    std::cout << "coverage tracing completed successfully.\n";
    std::cout << "output file: " << output_file << "\n";
    if (format == "drcov") {
      std::cout << "use 'w1tool read-drcov --file " << output_file << "' to analyze results.\n";
    }
  }

  return result;
}

} // namespace w1tool::commands
