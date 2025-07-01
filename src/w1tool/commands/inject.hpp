#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * Inject command - injects libraries into target processes
 *
 * @param library_flag Path to injection library
 * @param spawn_flag Spawn new process for injection
 * @param name_flag Target process name (optional)
 * @param pid_flag Target process ID (optional)
 * @param suspended_flag Start process in suspended state (optional)
 * @param args_list Binary and arguments (use -- to separate w1tool args from target args)
 * @return Exit code (0 for success, 1 for failure)
 */
int inject(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<std::string>& name_flag,
    args::ValueFlag<int>& pid_flag, args::Flag& suspended_flag, args::PositionalList<std::string>& args_list
);

} // namespace w1tool::commands