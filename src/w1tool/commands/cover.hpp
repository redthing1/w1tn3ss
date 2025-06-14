#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * Cover command - performs coverage tracing with configurable options
 *
 * @param binary_flag Path to binary to trace
 * @param pid_flag Process ID to attach to for runtime tracing
 * @param name_flag Process name to attach to for runtime tracing
 * @param output_flag Output file path for coverage data (optional)
 * @param exclude_system_flag Exclude system libraries from coverage (optional)
 * @param debug_flag Enable debug output (optional)
 * @param format_flag Output format (drcov, text) (optional)
 * @return Exit code (0 for success, 1 for failure)
 */
int cover(
    args::ValueFlag<std::string>& binary_flag, args::ValueFlag<int>& pid_flag, args::ValueFlag<std::string>& name_flag,
    args::ValueFlag<std::string>& output_flag, args::Flag& exclude_system_flag, args::Flag& debug_flag,
    args::ValueFlag<std::string>& format_flag
);

} // namespace w1tool::commands