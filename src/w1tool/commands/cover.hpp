#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * cover command - performs coverage tracing with configurable options
 *
 * @param library_flag path to w1cov library (auto-detected if not specified)
 * @param spawn_flag spawn new process for tracing
 * @param pid_flag process id to attach to for runtime tracing
 * @param name_flag process name to attach to for runtime tracing
 * @param output_flag output file path for coverage data (optional)
 * @param include_system_flag include system libraries in coverage (optional)
 * @param track_hitcounts_flag track hit counts in coverage data (optional)
 * @param module_filter_flag comma-separated list of modules to filter (optional)
 * @param debug_level_flag debug level override - defaults to passthrough verbosity (optional)
 * @param format_flag output format (drcov, text) (optional)
 * @param suspended_flag start process in suspended state (optional)
 * @param args_list binary and arguments (use -- to separate w1tool args from target args)
 * @param executable_path path to the current executable (for auto-discovery)
 * @return exit code (0 for success, 1 for failure)
 */
int cover(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag, args::Flag& include_system_flag,
    args::Flag& track_hitcounts_flag, args::Flag& inst_trace_flag, args::ValueFlag<std::string>& module_filter_flag,
    args::ValueFlag<int>& debug_level_flag, args::ValueFlag<std::string>& format_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list, const std::string& executable_path
);

} // namespace w1tool::commands