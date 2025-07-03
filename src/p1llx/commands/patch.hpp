#pragma once

#include <string>

namespace p1llx::commands {

/**
 * @brief Apply manual hex patch to file
 *
 * @param address_str Address to patch (hex string)
 * @param replace_data Replacement hex bytes
 * @param input_file Path to input binary file
 * @param output_file Path to output binary file
 * @return 0 for success, 1 for failure
 */
int patch(
    const std::string& address_str, const std::string& replace_data, const std::string& input_file,
    const std::string& output_file
);

} // namespace p1llx::commands