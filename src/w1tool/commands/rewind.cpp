#include "rewind.hpp"
#include "tracer.hpp"
#include "w1base/ext/args.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sstream>

#include <redlog.hpp>

// forward declare CLI symbols from main.cpp
namespace cli {
extern args::CounterFlag verbosity_flag;
}

namespace w1tool::commands {
namespace {

std::string normalize_token(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char ch : value) {
    if (ch == '-' || ch == '_' || ch == ' ') {
      continue;
    }
    out.push_back(static_cast<char>(std::tolower(ch)));
  }
  return out;
}

bool normalize_flow(const std::string& value, std::string& out) {
  const std::string token = normalize_token(value);
  if (token == "instruction" || token == "inst" || token == "instr") {
    out = "instruction";
    return true;
  }
  if (token == "block" || token == "basicblock" || token == "basic") {
    out = "block";
    return true;
  }
  return false;
}

bool normalize_stack_window(const std::string& value, std::string& out) {
  const std::string token = normalize_token(value);
  if (token == "none") {
    out = "none";
    return true;
  }
  if (token == "fixed") {
    out = "fixed";
    return true;
  }
  if (token == "frame") {
    out = "frame";
    return true;
  }
  return false;
}

bool normalize_mem_access(const std::string& value, std::string& out) {
  const std::string token = normalize_token(value);
  if (token == "none") {
    out = "none";
    return true;
  }
  if (token == "reads" || token == "read") {
    out = "reads";
    return true;
  }
  if (token == "writes" || token == "write") {
    out = "writes";
    return true;
  }
  if (token == "readswrites" || token == "readwrite" || token == "rw") {
    out = "reads_writes";
    return true;
  }
  return false;
}

bool normalize_threads(const std::string& value, std::string& out) {
  const std::string token = normalize_token(value);
  if (token == "main" || token == "mainonly") {
    out = "main";
    return true;
  }
  if (token == "auto" || token == "autoattach") {
    out = "auto";
    return true;
  }
  return false;
}

bool normalize_mem_filter(const std::string& value, std::string& out) {
  const std::string token = normalize_token(value);
  if (token == "all") {
    out = "all";
    return true;
  }
  if (token == "ranges" || token == "range") {
    out = "ranges";
    return true;
  }
  if (token == "stackwindow" || token == "stack") {
    out = "stack_window";
    return true;
  }
  return false;
}

std::string join_list(const std::vector<std::string>& items, char delimiter = ',') {
  if (items.empty()) {
    return "";
  }
  std::ostringstream joined;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i != 0) {
      joined << delimiter;
    }
    joined << items[i];
  }
  return joined.str();
}

std::string get_config_value_or(const std::map<std::string, std::string>& config, const char* key,
                                const char* fallback) {
  auto it = config.find(key);
  if (it != config.end()) {
    return it->second;
  }
  return fallback;
}

} // namespace

int rewind(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag,
    args::ValueFlag<std::string>& flow_flag, args::Flag& reg_deltas_flag,
    args::ValueFlag<uint64_t>& reg_snapshot_interval_flag, args::ValueFlag<std::string>& stack_window_mode_flag,
    args::ValueFlag<uint64_t>& stack_above_flag, args::ValueFlag<uint64_t>& stack_below_flag,
    args::ValueFlag<uint64_t>& stack_max_flag, args::ValueFlag<uint64_t>& stack_snapshot_interval_flag,
    args::ValueFlag<std::string>& mem_access_flag, args::Flag& mem_values_flag,
    args::ValueFlag<uint32_t>& mem_max_bytes_flag, args::ValueFlagList<std::string>& mem_filter_flag,
    args::ValueFlagList<std::string>& mem_ranges_flag, args::ValueFlag<std::string>& module_filter_flag,
    args::ValueFlag<std::string>& system_policy_flag, args::ValueFlag<std::string>& threads_flag,
    args::Flag& compress_flag, args::ValueFlag<uint32_t>& chunk_size_flag,
    args::ValueFlagList<std::string>& config_flags, args::ValueFlag<int>& debug_level_flag,
    args::Flag& suspended_flag, args::Flag& no_aslr_flag, args::PositionalList<std::string>& args_list,
    const std::string& executable_path
) {
  auto log = redlog::get_logger("w1tool.rewind");

  // build execution parameters
  tracer_execution_params params;
  params.tracer_name = "w1rewind";
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
    output_file = default_output_path(spawn_flag, args_list, ".w1r", "trace.w1r");
  }
  params.config_map["output"] = output_file;

  // set debug level
  apply_debug_level(params, debug_level_flag, args::get(cli::verbosity_flag));

  // set common config flags
  if (system_policy_flag) {
    params.config_map["system_policy"] = args::get(system_policy_flag);
  }
  if (module_filter_flag) {
    params.config_map["module_filter"] = args::get(module_filter_flag);
  }
  if (threads_flag) {
    std::string normalized;
    if (!normalize_threads(args::get(threads_flag), normalized)) {
      log.err("invalid threads value, expected: main, auto", redlog::field("threads", args::get(threads_flag)));
      return 1;
    }
    params.config_map["threads"] = normalized;
  }

  // flow and register options
  if (flow_flag) {
    std::string normalized;
    if (!normalize_flow(args::get(flow_flag), normalized)) {
      log.err("invalid flow value, expected: block, instruction", redlog::field("flow", args::get(flow_flag)));
      return 1;
    }
    params.config_map["flow"] = normalized;
  }
  if (reg_deltas_flag) {
    params.config_map["reg_deltas"] = "true";
  }
  if (reg_snapshot_interval_flag) {
    params.config_map["reg_snapshot_interval"] = std::to_string(args::get(reg_snapshot_interval_flag));
  }

  // stack options
  if (stack_window_mode_flag) {
    std::string normalized;
    if (!normalize_stack_window(args::get(stack_window_mode_flag), normalized)) {
      log.err(
          "invalid stack window mode, expected: none, fixed, frame",
          redlog::field("stack_window_mode", args::get(stack_window_mode_flag))
      );
      return 1;
    }
    params.config_map["stack_window_mode"] = normalized;
  }
  if (stack_above_flag) {
    params.config_map["stack_window_above"] = std::to_string(args::get(stack_above_flag));
  }
  if (stack_below_flag) {
    params.config_map["stack_window_below"] = std::to_string(args::get(stack_below_flag));
  }
  if (stack_max_flag) {
    params.config_map["stack_window_max"] = std::to_string(args::get(stack_max_flag));
  }
  if (stack_snapshot_interval_flag) {
    params.config_map["stack_snapshot_interval"] = std::to_string(args::get(stack_snapshot_interval_flag));
  }

  // memory options
  if (mem_access_flag) {
    std::string normalized;
    if (!normalize_mem_access(args::get(mem_access_flag), normalized)) {
      log.err(
          "invalid mem-access value, expected: none, reads, writes, reads_writes",
          redlog::field("mem_access", args::get(mem_access_flag))
      );
      return 1;
    }
    params.config_map["mem_access"] = normalized;
  }
  if (mem_values_flag) {
    params.config_map["mem_values"] = "true";
  }
  if (mem_max_bytes_flag) {
    params.config_map["mem_max_bytes"] = std::to_string(args::get(mem_max_bytes_flag));
  }
  if (mem_filter_flag) {
    std::vector<std::string> normalized_filters;
    for (const auto& entry : args::get(mem_filter_flag)) {
      std::string normalized;
      if (!normalize_mem_filter(entry, normalized)) {
        log.err(
            "invalid mem-filter value, expected: all, ranges, stack_window", redlog::field("mem_filter", entry)
        );
        return 1;
      }
      normalized_filters.push_back(normalized);
    }
    params.config_map["mem_filter"] = join_list(normalized_filters);
  }
  if (mem_ranges_flag) {
    params.config_map["mem_ranges"] = join_list(args::get(mem_ranges_flag));
    if (!mem_filter_flag && params.config_map.find("mem_filter") == params.config_map.end()) {
      params.config_map["mem_filter"] = "ranges";
    }
  }

  if (compress_flag) {
    params.config_map["compress"] = "true";
  }
  if (chunk_size_flag) {
    params.config_map["chunk_size"] = std::to_string(args::get(chunk_size_flag));
  }

  // set target
  std::string target_error;
  target_args target{spawn_flag, pid_flag, name_flag, suspended_flag, no_aslr_flag, args_list};
  if (!apply_target(params, target, &target_error)) {
    log.err(target_error);
    return 1;
  }

  const std::string flow = get_config_value_or(params.config_map, "flow", "block");
  const std::string mem_access = get_config_value_or(params.config_map, "mem_access", "none");
  const std::string stack_window = get_config_value_or(params.config_map, "stack_window_mode", "none");
  const std::string threads = get_config_value_or(params.config_map, "threads", "main");
  const std::string reg_deltas = get_config_value_or(params.config_map, "reg_deltas", "false");
  const std::string compress = get_config_value_or(params.config_map, "compress", "true");
  const std::string chunk_size = get_config_value_or(params.config_map, "chunk_size", "default");

  log.info(
      "rewind tracing configuration", redlog::field("output_file", output_file), redlog::field("flow", flow),
      redlog::field("mem_access", mem_access), redlog::field("stack_window", stack_window),
      redlog::field("threads", threads), redlog::field("reg_deltas", reg_deltas),
      redlog::field("compress", compress), redlog::field("chunk_size", chunk_size),
      redlog::field("debug_level", params.debug_level)
  );

  int result = execute_tracer_impl(params);

  if (result == 0) {
    if (!std::filesystem::exists(output_file)) {
      log.err("output file not created", redlog::field("output_file", output_file));
      return 1;
    }

    std::cout << "rewind trace completed successfully.\n";
    std::cout << "output file: " << output_file << "\n";
    std::cout << "use 'w1replay inspect -t " << output_file << "' to analyze results.\n";
  }

  return result;
}

} // namespace w1tool::commands
