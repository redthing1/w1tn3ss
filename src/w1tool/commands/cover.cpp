#include "cover.hpp"
#include "tracer.hpp"
#include "ext/args.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <redlog/redlog.hpp>

// forward declare CLI symbols from main.cpp
namespace cli {
extern args::CounterFlag verbosity_flag;
}

namespace w1tool::commands {

int cover(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag, args::Flag& exclude_system_flag,
    args::Flag& track_hitcounts_flag, args::ValueFlag<std::string>& module_filter_flag,
    args::ValueFlag<int>& debug_level_flag, args::ValueFlag<std::string>& format_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list, const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.cover");

  // validate target
  int target_count = 0;
  if (spawn_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }
  if (name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.err("exactly one target required: specify -s/--spawn, --pid, or --name");
    return 1;
  }

  // validate suspended flag
  if (suspended_flag && !spawn_flag) {
    log.err("--suspended can only be used with -s/--spawn (launch tracing)");
    return 1;
  }

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

  // determine output file
  std::string output_file;
  if (output_flag) {
    output_file = args::get(output_flag);
  } else {
    // generate default filename
    if (spawn_flag && !args_list.Get().empty()) {
      std::vector<std::string> all_args = args::get(args_list);
      std::string binary_path = all_args[0];
      std::filesystem::path fs_path(binary_path);
      std::string binary_name = fs_path.filename().string();
      output_file = binary_name + "_coverage." + format;
    } else {
      output_file = "coverage." + format;
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
  if (debug_level_flag) {
    params.debug_level = args::get(debug_level_flag);
  } else {
    params.debug_level = args::get(cli::verbosity_flag);
  }

  // translate cover flags to w1cov config
  params.config_map["exclude_system"] = exclude_system_flag ? "true" : "false";
  params.config_map["track_hitcounts"] = track_hitcounts_flag ? "true" : "false";
  params.config_map["output"] = output_file;

  if (module_filter_flag) {
    params.config_map["module_filter"] = args::get(module_filter_flag);
  }

  // set target
  if (spawn_flag) {
    if (args_list.Get().empty()) {
      log.err("binary path required when using -s/--spawn flag");
      return 1;
    }

    std::vector<std::string> all_args = args::get(args_list);
    params.spawn_target = true;
    params.binary_path = all_args[0];
    params.suspended = suspended_flag;

    // extract binary arguments
    if (all_args.size() > 1) {
      params.binary_args.assign(all_args.begin() + 1, all_args.end());
    }

  } else if (pid_flag) {
    params.target_pid = args::get(pid_flag);

  } else if (name_flag) {
    params.process_name = args::get(name_flag);
  }

  log.info(
      "coverage tracing configuration", redlog::field("output_file", output_file), redlog::field("format", format),
      redlog::field("exclude_system", exclude_system_flag ? "true" : "false"),
      redlog::field("track_hitcounts", track_hitcounts_flag ? "true" : "false"),
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