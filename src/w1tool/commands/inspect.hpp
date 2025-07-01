#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * inspect command - analyzes binary files
 *
 * @param binary_flag path to binary file to inspect
 * @return exit code (0 for success, 1 for failure)
 */
int inspect(args::ValueFlag<std::string>& binary_flag);

} // namespace w1tool::commands