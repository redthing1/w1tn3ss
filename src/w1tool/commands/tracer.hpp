#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * tracer command - generic tracer launcher with flexible configuration
 *
 * @param library_flag path to tracer library (auto-detected if not specified)
 * @param name_flag tracer name (w1cov, w1mem, mintrace, etc.)
 * @param spawn_flag spawn new process for tracing
 * @param pid_flag process id to attach to for runtime tracing
 * @param process_name_flag process name to attach to for runtime tracing
 * @param config_flags key=value pairs for environment variables
 * @param debug_level_flag debug level override - defaults to passthrough verbosity
 * @param list_tracers_flag list available tracers and exit
 * @param suspended_flag start process in suspended state (optional)
 * @param args_list binary and arguments (use -- to separate w1tool args from target args)
 * @param executable_path path to the current executable (for auto-discovery)
 * @return exit code (0 for success, 1 for failure)
 */
int tracer(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::Flag& spawn_flag,
    args::ValueFlag<int>& pid_flag, args::ValueFlag<std::string>& process_name_flag,
    args::ValueFlagList<std::string>& config_flags, args::ValueFlag<int>& debug_level_flag,
    args::Flag& list_tracers_flag, args::Flag& suspended_flag, args::PositionalList<std::string>& args_list,
    const std::string& executable_path
);

} // namespace w1tool::commands