#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * Inject command - injects libraries into target processes
 *
 * @param library_flag Path to injection library
 * @param name_flag Target process name (optional)
 * @param pid_flag Target process ID (optional)
 * @param binary_flag Binary to launch with injection (optional)
 * @return Exit code (0 for success, 1 for failure)
 */
int inject(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& binary_flag
);

} // namespace w1tool::commands