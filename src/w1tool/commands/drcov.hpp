#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * DrCov command - analyzes DrCov coverage files
 * 
 * @param file_flag Path to DrCov file to analyze
 * @param summary_flag Show summary only (optional)
 * @param detailed_flag Show detailed basic block listing (optional)
 * @param module_flag Filter by module name substring (optional)
 * @return Exit code (0 for success, 1 for failure)
 */
int drcov(args::ValueFlag<std::string>& file_flag,
          args::Flag& summary_flag,
          args::Flag& detailed_flag,
          args::ValueFlag<std::string>& module_flag);

} // namespace w1tool::commands