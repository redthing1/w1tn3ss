#include "dump.hpp"
#include "tracer.hpp"
#include "ext/args.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <redlog.hpp>

// forward declare cli symbols from main.cpp
namespace cli {
extern args::CounterFlag verbosity_flag;
}

namespace w1tool::commands {

int dump(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag, args::Flag& memory_flag,
    args::ValueFlagList<std::string>& filter_flag, args::ValueFlag<std::string>& max_region_size_flag,
    args::ValueFlag<int>& debug_level_flag, args::Flag& suspended_flag, args::PositionalList<std::string>& args_list,
    const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.dump");

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
      output_file = binary_name + ".w1dump";
    } else {
      output_file = "process.w1dump";
    }
  }

  // build execution parameters
  tracer_execution_params params;
  params.tracer_name = "w1dump";
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

  // translate dump flags to w1dump config
  params.config_map["output"] = output_file;
  params.config_map["dump_memory_content"] = memory_flag ? "true" : "false";

  // parse and validate filters
  if (filter_flag) {
    std::vector<std::string> filter_strings = args::get(filter_flag);
    for (size_t i = 0; i < filter_strings.size(); i++) {
      // filters are passed as filter_0, filter_1, etc.
      params.config_map["filter_" + std::to_string(i)] = filter_strings[i];
    }
    params.config_map["filter_count"] = std::to_string(filter_strings.size());
  }

  // parse max region size
  if (max_region_size_flag) {
    std::string size_str = args::get(max_region_size_flag);
    params.config_map["max_region_size"] = size_str;
  }

  // dump on entry is always true for this command
  params.config_map["dump_on_entry"] = "true";

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
      "process dump configuration", redlog::field("output_file", output_file),
      redlog::field("dump_memory", memory_flag ? "true" : "false"),
      redlog::field("filter_count", filter_flag ? args::get(filter_flag).size() : 0),
      redlog::field("debug_level", params.debug_level)
  );

  // execute w1dump tracing
  int result = execute_tracer_impl(params);

  // handle dump post-processing
  if (result == 0) {
    // check output file created
    if (!std::filesystem::exists(output_file)) {
      log.err("output file not created", redlog::field("output_file", output_file));
      return 1;
    }

    std::cout << "process dump completed successfully.\n";
    std::cout << "output file: " << output_file << "\n";
    std::cout << "use 'w1tool read-dump --file " << output_file << "' to analyze results.\n";
  }

  return result;
}

} // namespace w1tool::commands