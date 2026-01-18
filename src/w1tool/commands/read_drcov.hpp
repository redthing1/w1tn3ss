#pragma once

#include "w1base/ext/args.hpp"

namespace w1tool::commands {

/**
 * read-DrCov command - analyzes DrCov coverage files
 *
 * @param file_flag path to DrCov file to analyze
 * @param summary_flag show summary only (optional)
 * @param detailed_flag show detailed basic block listing (optional)
 * @param module_flag filter by module name substring (optional)
 * @return exit code (0 for success, 1 for failure)
 */
int read_drcov(
    args::ValueFlag<std::string>& file_flag, args::Flag& summary_flag, args::Flag& detailed_flag,
    args::ValueFlag<std::string>& module_flag
);

} // namespace w1tool::commands