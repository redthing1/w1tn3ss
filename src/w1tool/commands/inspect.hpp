#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

/**
 * inspect command - comprehensive binary analysis using LIEF
 *
 * @param binary_flag path to binary file to inspect
 * @param detailed_flag show detailed analysis (optional)
 * @param sections_flag show section/segment information (optional)
 * @param symbols_flag show symbol table information (optional)
 * @param imports_flag show import/export information (optional)
 * @param security_flag show security features analysis (optional)
 * @param json_flag output results in JSON format (optional)
 * @param format_flag force specific format interpretation (optional)
 * @return exit code (0 for success, 1 for failure)
 */
int inspect(
    args::ValueFlag<std::string>& binary_flag,
    args::Flag& detailed_flag,
    args::Flag& sections_flag,
    args::Flag& symbols_flag,
    args::Flag& imports_flag,
    args::Flag& security_flag,
    args::Flag& json_flag,
    args::ValueFlag<std::string>& format_flag
);

} // namespace w1tool::commands