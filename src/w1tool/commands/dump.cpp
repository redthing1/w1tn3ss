#include "dump.hpp"
#include "tracer.hpp"
#include "w1base/ext/args.hpp"
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
    args::ValueFlagList<std::string>& config_flags, args::ValueFlagList<std::string>& filter_flag,
    args::ValueFlag<std::string>& max_region_size_flag, args::ValueFlag<int>& debug_level_flag,
    args::Flag& suspended_flag, args::Flag& no_aslr_flag, args::PositionalList<std::string>& args_list,
    const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.dump");

  // build execution parameters
  tracer_execution_params params;
  params.tracer_name = "w1dump";
  params.executable_path = executable_path;

  if (library_flag) {
    params.library_path = args::get(library_flag);
  }

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
    output_file = default_output_path(spawn_flag, args_list, ".w1dump", "process.w1dump");
  }

  // set debug level
  apply_debug_level(params, debug_level_flag, args::get(cli::verbosity_flag));

  // translate dump flags to w1dump config
  params.config_map["output"] = output_file;
  if (memory_flag) {
    params.config_map["dump_memory_content"] = "true";
  } else if (params.config_map.find("dump_memory_content") == params.config_map.end()) {
    params.config_map["dump_memory_content"] = "false";
  }

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
  std::string target_error;
  target_args target{spawn_flag, pid_flag, name_flag, suspended_flag, no_aslr_flag, args_list};
  if (!apply_target(params, target, &target_error)) {
    log.err(target_error);
    return 1;
  }

  std::string dump_memory = "false";
  if (auto it = params.config_map.find("dump_memory_content"); it != params.config_map.end()) {
    dump_memory = it->second;
  }
  size_t filter_count = 0;
  if (auto it = params.config_map.find("filter_count"); it != params.config_map.end()) {
    try {
      filter_count = static_cast<size_t>(std::stoull(it->second));
    } catch (...) {
      filter_count = 0;
    }
  }
  log.info(
      "process dump configuration", redlog::field("output_file", output_file),
      redlog::field("dump_memory", dump_memory), redlog::field("filter_count", filter_count),
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
