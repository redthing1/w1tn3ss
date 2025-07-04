#pragma once

#include <string>

namespace p1llx::commands {

/**
 * @brief Apply auto-cure lua script to static file
 *
 * @param script_path Path to lua cure script
 * @param input_file Path to input binary file
 * @param output_file Path to output binary file
 * @param platform_override Optional platform override (e.g., "linux:x64", "darwin:arm64")
 * @return 0 for success, 1 for failure
 */
int cure(
    const std::string& script_path, const std::string& input_file, const std::string& output_file,
    const std::string& platform_override = ""
);

} // namespace p1llx::commands